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
	"golang.org/x/term"
)

func (s *service) socket() string { return filepath.Join(s.state, "session.sock") }

func (s *service) checkSocketPath() error {
	if len(s.socket()) >= len(unix.RawSockaddrUnix{}.Path) {
		return errors.New("vault path is too long for a local socket; choose a shorter private directory with --state-dir")
	}
	return nil
}

func (s *service) serve() error {
	if err := s.checkSocketPath(); err != nil {
		return err
	}
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
			_ = c.SetDeadline(time.Now().Add(16 * time.Minute))
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

func (s *service) connect(deadline time.Time) (*net.UnixConn, error) {
	info, err := os.Lstat(s.socket())
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return nil, errors.New("invalid helper socket; unexpected file preserved")
	}
	dialer := net.Dialer{Deadline: deadline}
	conn, err := dialer.Dial("unix", s.socket())
	if err != nil {
		return nil, err
	}
	c := conn.(*net.UnixConn)
	if !samePeer(c) {
		c.Close()
		return nil, errors.New("unexpected daemon owner")
	}
	return c, nil
}
func (s *service) rpc(r request) (json.RawMessage, error) {
	if err := s.checkSocketPath(); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(s.state); errors.Is(err, os.ErrNotExist) {
		switch r.Op {
		case "setup", "restore", "import":
			// The first helper creates its private state directory.
		case "config-discard":
			return json.Marshal(s.status())
		default:
			return nil, errors.New("no vault in this directory; run kubeconfig-vault setup first")
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	c, err := s.connect(deadline)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("cannot connect to the private helper: %w", err)
		}
		cmd := exec.Command(s.executable, "--state-dir", s.state, "--session-seconds", fmt.Sprint(int(s.ttl.Seconds())), "--browser", s.browser, "serve")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err = cmd.Start(); err != nil {
			return nil, errors.New("cannot start private daemon")
		}
		go func() { _ = cmd.Wait() }()
		for time.Now().Before(deadline) {
			time.Sleep(30 * time.Millisecond)
			c, err = s.connect(deadline)
			if err == nil {
				break
			}
		}
		if err != nil {
			return nil, errors.New("daemon did not start; run serve in the foreground for the reason")
		}
	}
	return exchangeRPC(c, r, time.Now().Add(16*time.Minute))
}

func exchangeRPC(c *net.UnixConn, r request, deadline time.Time) (json.RawMessage, error) {
	defer c.Close()
	if err := c.SetDeadline(deadline); err != nil {
		return nil, err
	}
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
		missing = "no generated kubeconfig; run kubeconfig-vault status, or kubeconfig-vault setup for a new vault"
	case "edit":
		name = filepath.Join(state, "edit", "kubeconfig")
		missing = "no editable kubeconfig; run config unlock or check status for an interrupted edit"
	case "vault":
		name = filepath.Join(state, "current", "vault.age")
		missing = "no encrypted vault at this path; run kubeconfig-vault status, or kubeconfig-vault setup for a new vault"
	default:
		return errors.New(usage)
	}
	if args[0] == "edit" {
		if err := checkPrivateDir(filepath.Dir(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
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

func runRecover(args []string) error {
	const usage = "usage: recover VAULT.age [--key FILE] --check|--out NEW-FILE"
	if len(args) < 2 || args[0] == "" {
		return errors.New(usage)
	}
	var key, out string
	var check bool
	for i := 1; i < len(args); i++ {
		switch option := args[i]; option {
		case "--check":
			if check {
				return errors.New(usage)
			}
			check = true
		case "--key", "--out":
			i++
			if i == len(args) || args[i] == "" || strings.HasPrefix(args[i], "--") {
				return errors.New(usage)
			}
			if option == "--key" && key == "" {
				key = args[i]
			} else if option == "--out" && out == "" {
				out = args[i]
			} else {
				return errors.New(usage)
			}
		default:
			return errors.New(usage)
		}
	}
	if check == (out != "") {
		return errors.New(usage)
	}
	if err := recoverFile(args[0], key, out); err != nil {
		return err
	}
	if out != "" {
		fmt.Fprintln(os.Stdout, "Portable plaintext config recovered to the selected file.")
	}
	return nil
}

// Set from the release tag when packaging a binary.
var version = "dev"

func run(args []string) error {
	f := flag.NewFlagSet(commandName, flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	state := f.String("state-dir", "", "vault state directory (uses the platform default if omitted)")
	seconds := f.Int("session-seconds", 3600, "absolute session lifetime (1–3600 seconds; new daemon only)")
	browser := f.String("browser", "", "browser executable; default is open/xdg-open")
	showVersion := f.Bool("version", false, "print the build version")
	var showHelp bool
	f.BoolVar(&showHelp, "h", false, "show help")
	f.BoolVar(&showHelp, "help", false, "show help")
	f.Usage = func() { fmt.Fprintln(f.Output(), "Run kubeconfig-vault --help for usage.") }
	if err := f.Parse(args); err != nil {
		return errors.New("invalid command options")
	}
	if *showVersion {
		fmt.Fprintln(os.Stdout, commandName, version)
		return nil
	}
	a := f.Args()
	if showHelp || len(a) == 0 {
		return printHelp(os.Stdout, a)
	}
	if a[0] == "help" {
		return printHelp(os.Stdout, a[1:])
	}
	if last := a[len(a)-1]; last == "--help" || last == "-h" {
		return printHelp(os.Stdout, a[:len(a)-1])
	}
	if len(a) == 1 && a[0] == "config" {
		return printHelp(os.Stdout, a)
	}
	if a[0] == "edit" {
		if len(a) != 1 {
			return errors.New("usage: kubeconfig-vault edit")
		}
		a = []string{"config", "edit"}
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
		return runRecover(a[1:])
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
	if a[0] == "status" {
		if len(a) > 2 || len(a) == 2 && a[1] != "--json" {
			return errors.New("usage: status [--json]")
		}
		s := &service{state: *state}
		return s.printStatus(len(a) == 2 || !term.IsTerminal(int(os.Stdout.Fd())))
	}
	if a[0] == "lock" || a[0] == "stop" {
		if len(a) > 2 || len(a) == 2 && a[1] != "--json" {
			return fmt.Errorf("usage: %s [--json]", a[0])
		}
		return (&service{state: *state}).endSession(a[0], len(a) == 2 || !term.IsTerminal(int(os.Stdout.Fd())))
	}
	executable, err := os.Executable()
	if err != nil {
		return errors.New("cannot resolve application executable")
	}
	s := &service{state: *state, executable: installedCommand(executable), browser: *browser, ttl: time.Duration(*seconds) * time.Second, stop: make(chan struct{})}
	if a[0] == "setup" {
		return s.setupCommand(a[1:])
	}
	if err = checkPrivateDir(*state); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if a[0] == "import" || a[0] == "restore" {
		if err := s.checkSocketPath(); err != nil {
			return err
		}
	}
	if a[0] == "serve" {
		if len(a) != 1 {
			return errors.New("unexpected serve argument")
		}
		return s.serve()
	}
	if a[0] == "history" {
		return s.history(a[1:])
	}
	if a[0] == "restore" {
		if len(a) != 2 && (len(a) != 4 || a[2] != "--key") {
			return errors.New("usage: restore VAULT.age [--key FILE]")
		}
		if id, err := currentID(s.state); err != nil || id != "" {
			return errors.New("restore requires an unused vault directory")
		}
		path, err := absolute(a[1])
		if err != nil {
			return err
		}
		r := request{Op: "restore", Path: path}
		if len(a) == 4 {
			r.Recovery, err = absolute(a[3])
			if err != nil {
				return err
			}
		} else {
			if err := checkBackupInput(path); err != nil {
				return err
			}
			key, err := promptRecoveryKey()
			if err != nil {
				return err
			}
			r.RecoveryIdentity = []byte(key.String())
			defer clear(r.RecoveryIdentity)
		}
		return s.clientAction(r)
	}
	if a[0] == "backup" {
		if len(a) == 3 && a[1] == "--compare" {
			if err := compareBackup(s.state, a[2]); err != nil {
				return err
			}
			fmt.Fprintln(os.Stdout, "Backup matches the current encrypted save.")
			return nil
		}
		if len(a) != 2 || a[1] == "--compare" {
			return errors.New("usage: backup NEW-FILE or backup --compare FILE")
		}
		if err := backupGeneration(s.state, a[1]); err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, "Encrypted backup created. Keep your offline recovery key separately.")
		return nil
	}
	if len(a) >= 2 && a[0] == "config" {
		if a[1] == "edit" && len(a) == 2 {
			return s.editConfig()
		}
		if a[1] == "link" || a[1] == "unlink" || a[1] == "repair" {
			return s.clientLink(a[1], a[2:])
		}
	}
	r := request{Op: a[0]}
	switch a[0] {
	case "unlock":
		if len(a) != 1 {
			return errors.New("unexpected command argument")
		}
	case "import":
		switch {
		case len(a) == 1:
			r.Path, err = defaultKubeconfigPath()
		case len(a) == 2 || len(a) == 4 && a[2] == "--recovery-key":
			r.Path, err = absolute(a[1])
		default:
			return errors.New("usage: import [SOURCE] or import SOURCE --recovery-key FILE")
		}
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
			return errors.New("usage: config unlock|lock|discard|link|unlink")
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

	if r.Op == "config-lock" {
		return reportSavedEdit(result, false)
	}
	fmt.Fprintln(os.Stdout, strings.TrimSpace(string(result)))
	if r.Op == "import" && len(r.RecoveryIdentity) != 0 {
		fmt.Fprintln(os.Stderr, "Vault created. Use config link to connect clients that use the default kubeconfig.")
	}
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
