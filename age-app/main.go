package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func (s *service) socket() string { return filepath.Join(s.state, "session.sock") }
func (s *service) serve() error {
	if err := privateDir(s.state); err != nil {
		return err
	}
	fd, err := unix.Open(filepath.Join(s.state, "daemon.lock"), unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return errors.New("cannot open daemon lock")
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != uint32(os.Getuid()) || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0077 != 0 || st.Nlink != 1 {
		return errors.New("unsafe daemon lock file")
	}
	if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return errors.New("a daemon is already running")
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	if info, e := os.Lstat(s.socket()); e == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("refusing to replace a non-socket path")
		}
		if os.Remove(s.socket()) != nil {
			return errors.New("cannot remove stale socket")
		}
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.socket(), Net: "unix"})
	if err != nil {
		return errors.New("cannot bind private socket (state path may be too long)")
	}
	defer l.Close()
	if err = os.Chmod(s.socket(), 0600); err != nil {
		return errors.New("cannot protect private socket")
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sig)
	go func() {
		select {
		case <-s.stop:
		case <-sig:
			s.lock(true)
		}
		_ = l.Close()
	}()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-ticker.C:
				s.mu.Lock()
				s.expireLocked()
				s.mu.Unlock()
			case <-done:
				return
			}
		}
	}()
	slots := make(chan struct{}, 16)
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			select {
			case <-s.stop:
				return nil
			default:
			}
			return nil
		}
		select {
		case slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		go func() {
			defer func() { <-slots }()
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(6 * time.Minute))
			if !samePeer(c) {
				return
			}
			reader := bufio.NewReader(io.LimitReader(c, maxSource+65536))
			b, err := reader.ReadBytes('\n')
			if err != nil || len(b) > maxSource+32768 {
				return
			}
			defer clear(b)
			var r request
			defer func() { clear(r.RecoveryIdentity) }()
			if decodeJSON(b, &r) != nil {
				_ = json.NewEncoder(c).Encode(response{Error: "invalid local request"})
				return
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			// A killed kubectl/CLI must not leave an authentication operation alive.
			go func() { _, _ = reader.ReadByte(); cancel() }()
			result, err := s.handle(ctx, r)
			out := response{Result: result}
			if err != nil {
				out = response{Error: err.Error()}
			}
			_ = json.NewEncoder(c).Encode(out)
		}()
	}
}

func (s *service) connect() (*net.UnixConn, error) {
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: s.socket(), Net: "unix"})
	if err != nil {
		return nil, err
	}
	if !samePeer(c) {
		c.Close()
		return nil, errors.New("unexpected daemon owner")
	}
	return c, nil
}
func (s *service) rpc(r request) (json.RawMessage, error) {
	c, err := s.connect()
	if err != nil {
		cmd := exec.Command(s.executable, "--state-dir", s.state, "--session-seconds", fmt.Sprint(int(s.ttl.Seconds())), "--browser", s.browser, "serve")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err = cmd.Start(); err != nil {
			return nil, errors.New("cannot start private daemon")
		}
		go func() { _ = cmd.Wait() }()
		for i := 0; i < 100; i++ {
			time.Sleep(30 * time.Millisecond)
			c, err = s.connect()
			if err == nil {
				break
			}
		}
		if err != nil {
			return nil, errors.New("daemon did not start; run serve in the foreground for the reason")
		}
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(6 * time.Minute))
	if json.NewEncoder(c).Encode(r) != nil {
		return nil, errors.New("cannot send local request")
	}
	var reply struct {
		Error  string          `json:"error"`
		Result json.RawMessage `json:"result"`
	}
	if json.NewDecoder(io.LimitReader(c, maxSource+65536)).Decode(&reply) != nil {
		return nil, errors.New("local operation failed or timed out")
	}
	if reply.Error != "" {
		return nil, errors.New(reply.Error)
	}
	return reply.Result, nil
}

func absolute(path string) (string, error) {
	if path == "" {
		return "", errors.New("a file path is required")
	}
	return filepath.Abs(path)
}

func printPath(state string, args []string) error {
	const usage = "usage: path kubeconfig|edit|vault"
	if len(args) != 1 {
		return errors.New(usage)
	}
	var name, missing string
	switch args[0] {
	case "kubeconfig":
		name = filepath.Join(state, "current", "kubeconfig")
		missing = "no generated kubeconfig; run import first"
	case "edit":
		name = filepath.Join(state, "edit", "kubeconfig")
		missing = "no editable kubeconfig; run config unlock or check status for an interrupted edit"
	case "vault":
		name = filepath.Join(state, "current", "vault.age")
		missing = "no encrypted vault; run import first"
	default:
		return errors.New(usage)
	}
	info, err := os.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New(missing)
	}
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("expected a regular file at the requested path")
	}
	_, err = fmt.Fprintln(os.Stdout, name)
	return err
}

// Set from the release tag when packaging a binary.
var version = "dev"

func run(args []string) error {
	f := flag.NewFlagSet("kube-unlock-age", flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	state := f.String("state-dir", "", "vault state directory (uses the platform default if omitted)")
	seconds := f.Int("session-seconds", 3600, "absolute session lifetime (1–3600 seconds; new daemon only)")
	browser := f.String("browser", "", "browser executable; default is open/xdg-open")
	showVersion := f.Bool("version", false, "print the build version")
	f.Usage = func() {
		fmt.Fprintln(os.Stderr, `Kubeconfig Vault (experimental)
Usage: kube-unlock-age [global options] COMMAND

recovery-key new FILE                  Create a new private offline recovery key
recovery-key public FILE               Print only its public recipient
import SOURCE                         Show a recovery key, then enroll and verify a vault
import SOURCE --recovery-key FILE      Enroll and verify a vault using an existing recovery key
path kubeconfig|edit|vault              Print the path to an existing file
credential ID                         Kubernetes exec entry point (not for humans)
unlock | lock | status | stop          Manage the one-hour credential session
config unlock                         Create a plaintext file for normal editing
config lock [--accept-connection-changes]  Validate, encrypt, verify, and delete edit
config discard                        Delete the unsaved plaintext edit
export NEW-FILE                        Fresh authentication; portable plaintext export
recover VAULT.age --out NEW-FILE       Paste your recovery key at a hidden prompt
recover VAULT.age --key FILE --out NEW-FILE  Recover using a private key file
serve                                 Foreground daemon for troubleshooting

Global options must precede COMMAND. Import preserves the original source.
Lock and stop preserve open edits; status reports fully_locked=false in that case.`)
		f.PrintDefaults()
	}
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return errors.New("invalid command options")
	}
	if *showVersion {
		fmt.Fprintln(os.Stdout, "kube-unlock-age", version)
		return nil
	}
	a := f.Args()
	if len(a) == 0 {
		f.Usage()
		return nil
	}
	if *seconds < 1 || *seconds > 3600 {
		return errors.New("session lifetime must be 1–3600 seconds")
	}
	if a[0] == "recovery-key" {
		if len(a) != 3 {
			return errors.New("usage: recovery-key new|public FILE")
		}
		p, err := absolute(a[2])
		if err != nil {
			return err
		}
		switch a[1] {
		case "new":
			if err = createRecovery(p); err != nil {
				return err
			}
			fmt.Fprintln(os.Stdout, "Recovery key written. Keep this private file offline, separately from the vault.")
			return nil
		case "public":
			key, err := readRecovery(p)
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stdout, key.Recipient().String())
			return nil
		default:
			return errors.New("unknown recovery-key command")
		}
	}
	if a[0] == "recover" {
		switch {
		case len(a) == 4 && a[2] == "--out":
			if err := recoverFromTerminal(a[1], a[3]); err != nil {
				return err
			}
		case len(a) == 6 && a[2] == "--key" && a[4] == "--out":
			if err := recoverFile(a[1], a[3], a[5]); err != nil {
				return err
			}
		default:
			return errors.New("usage: recover VAULT.age [--key FILE] --out NEW-FILE")
		}
		fmt.Fprintln(os.Stdout, "Portable plaintext config recovered to the selected file.")
		return nil
	}
	if *state == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return errors.New("cannot resolve home directory")
		}
		if runtime.GOOS == "darwin" {
			*state = filepath.Join(home, "Library", "Application Support", "kube-unlock-age")
		} else {
			*state = filepath.Join(home, ".local", "share", "kube-unlock-age")
		}
	}
	var err error
	*state, err = filepath.Abs(*state)
	if err != nil {
		return errors.New("invalid state directory")
	}
	if a[0] == "path" {
		return printPath(*state, a[1:])
	}
	if err = privateDir(*state); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return errors.New("cannot resolve application executable")
	}
	s := &service{state: *state, executable: executable, browser: *browser, ttl: time.Duration(*seconds) * time.Second, stop: make(chan struct{})}
	if a[0] == "serve" {
		if len(a) != 1 {
			return errors.New("unexpected serve argument")
		}
		return s.serve()
	}
	r := request{Op: a[0]}
	switch a[0] {
	case "status", "lock", "stop", "unlock":
		if len(a) != 1 {
			return errors.New("unexpected command argument")
		}
	case "import":
		if len(a) != 2 && (len(a) != 4 || a[2] != "--recovery-key") {
			return errors.New("usage: import SOURCE [--recovery-key FILE]")
		}
		r.Path, err = absolute(a[1])
		if err != nil {
			return err
		}
		if len(a) == 4 {
			r.Recovery, err = absolute(a[3])
			if err != nil {
				return err
			}
		} else {
			// Validate before asking the user to save a key. The daemon checks
			// again under its operation lock before touching the vault.
			if _, err = s.prepareImport(r.Path); err != nil {
				return err
			}
			r.RecoveryIdentity, err = showNewRecoveryKey()
			if err != nil {
				return err
			}
			defer clear(r.RecoveryIdentity)
		}
	case "export":
		if len(a) != 2 {
			return errors.New("usage: export NEW-FILE")
		}
		r.Path, err = absolute(a[1])
		if err != nil {
			return err
		}
	case "config":
		if len(a) < 2 || len(a) > 3 {
			return errors.New("usage: config unlock|lock|discard")
		}
		r.Op = "config-" + a[1]
		if a[1] != "unlock" && a[1] != "lock" && a[1] != "discard" {
			return errors.New("unknown config command")
		}
		if len(a) == 3 {
			if a[1] != "lock" || a[2] != "--accept-connection-changes" {
				return errors.New("unexpected config option")
			}
			r.Accept = true
		}
	case "credential":
		if len(a) != 2 {
			return errors.New("credential ID is required")
		}
		r.ID = a[1]
		info := os.Getenv("KUBERNETES_EXEC_INFO")
		if len(info) > maxSource || info == "" {
			return errors.New("missing or oversized Kubernetes exec information")
		}
		var input struct {
			APIVersion string `json:"apiVersion"`
			Kind       string `json:"kind"`
			Spec       struct {
				Cluster *struct {
					cluster
					Config json.RawMessage `json:"config"`
				} `json:"cluster"`
				Interactive bool `json:"interactive"`
			} `json:"spec"`
		}
		if decodeJSON([]byte(info), &input) != nil || input.APIVersion != "client.authentication.k8s.io/v1" || input.Kind != "ExecCredential" || input.Spec.Cluster == nil {
			return errors.New("unsupported Kubernetes exec information")
		}
		if len(input.Spec.Cluster.Config) != 0 && string(input.Spec.Cluster.Config) != "null" {
			return errors.New("per-cluster exec extensions are not supported")
		}
		r.Cluster = &input.Spec.Cluster.cluster
	default:
		return errors.New("unknown command; use --help")
	}
	result, err := s.rpc(r)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, strings.TrimSpace(string(result)))
	return nil
}

func main() {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		fmt.Fprintln(os.Stderr, "Cannot disable core dumps.")
		os.Exit(1)
	}
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
