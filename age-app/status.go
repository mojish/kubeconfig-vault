package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const statusTimeout = 2 * time.Second

var errStaleSocket = errors.New("helper socket is present but no helper is listening")

type clientStatus struct {
	Configured    bool     `json:"configured"`
	HelperRunning bool     `json:"helper_running"`
	Unlocked      bool     `json:"unlocked"`
	FullyLocked   bool     `json:"fully_locked"`
	EditOpen      bool     `json:"edit_open"`
	EditPath      string   `json:"edit_path,omitempty"`
	EditPaths     []string `json:"edit_paths,omitempty"`
	Kubeconfig    string   `json:"kubeconfig"`
	Problems      []string `json:"problems,omitempty"`
	NextAction    string   `json:"next_action,omitempty"`
	PausedUntil   string   `json:"automatic_unlock_paused_until,omitempty"`
	ExpiresAt     string   `json:"expires_at,omitempty"`
}

func (v *clientStatus) problem(message, action string) {
	v.Problems = append(v.Problems, message)
	if v.NextAction == "" {
		v.NextAction = action
	}
	v.FullyLocked = false
}

// Only inspect directory entries. Status never needs the contents of these files.
func (s *service) inspectGeneration(v *clientStatus) {
	id, err := currentID(s.state)
	generations := filepath.Join(s.state, "generations")
	if err == nil && id == "" {
		if _, err := os.Lstat(generations); errors.Is(err, os.ErrNotExist) {
			return
		}
	}
	const recoverAction = "Preserve the vault directory. Check an encrypted backup with kubeconfig-vault recover BACKUP.age --check."
	if err != nil || id == "" {
		v.problem("active generation link is missing or invalid", recoverAction)
		return
	}
	dir := filepath.Join(generations, id)
	for _, path := range []string{generations, dir} {
		if checkPrivateDir(path) != nil {
			v.problem("active vault generation directory is missing or unsafe", recoverAction)
			return
		}
	}
	good := true
	for _, file := range []struct {
		name  string
		limit int64
	}{
		{"vault.age", maxVault}, {"metadata.json", 65536}, {"kubeconfig", maxSource},
	} {
		var st unix.Stat_t
		err := unix.Lstat(filepath.Join(dir, file.name), &st)
		if err == nil && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&0077 == 0 && st.Mode&0400 != 0 &&
			st.Nlink == 1 && st.Uid == uint32(os.Getuid()) && st.Size > 0 && st.Size <= file.limit {
			continue
		}
		good = false
		message := file.name + " is unsafe or unavailable"
		if errors.Is(err, os.ErrNotExist) {
			message = file.name + " is missing"
		}
		action := recoverAction
		if file.name == "kubeconfig" && errors.Is(err, os.ErrNotExist) {
			action = "For a linked client, run kubeconfig-vault config repair. For a custom path, add --kubeconfig FILE."
		} else if err == nil && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Uid == uint32(os.Getuid()) && st.Nlink == 1 && st.Mode&0400 == 0 {
			action = "Restore owner read permission on the private file and rerun kubeconfig-vault status."
		} else if file.name != "vault.age" {
			action = "Preserve the encrypted vault with kubeconfig-vault backup NEW-FILE."
		}
		v.problem(message, action)
	}
	v.Configured = good
}

// If the socket was removed while the daemon still owns its lock, the
// session state is unknown. Probe the lock without creating or reading it.
func (s *service) stoppedHelper() error {
	path := filepath.Join(s.state, "daemon.lock")
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("cannot inspect helper lock")
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&0077 != 0 || st.Uid != uint32(os.Getuid()) {
		return errors.New("unsafe helper lock")
	}
	if unix.Flock(fd, unix.LOCK_SH|unix.LOCK_NB) != nil {
		return errors.New("helper lock is held or unavailable while its socket is missing")
	}
	return nil
}

func (s *service) runningConnection(deadline time.Time) (*net.UnixConn, error) {
	socket, err := os.Lstat(s.socket())
	if errors.Is(err, os.ErrNotExist) {
		return nil, s.stoppedHelper()
	}
	if err != nil || socket.Mode()&os.ModeSocket == 0 {
		return nil, errors.New("invalid helper socket")
	}
	conn, err := s.connect(deadline)
	if errors.Is(err, syscall.ECONNREFUSED) {
		return nil, errStaleSocket
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, s.stoppedHelper()
	}
	if err != nil {
		return nil, errors.New("cannot connect to helper")
	}
	return conn, nil
}

func (s *service) liveStatus() (*clientStatus, error) {
	deadline := time.Now().Add(statusTimeout)
	conn, err := s.runningConnection(deadline)
	if err != nil || conn == nil {
		return nil, err
	}
	reply, err := exchangeRPC(conn, request{Op: "status"}, deadline)
	if err != nil {
		return nil, errors.New("helper did not return status")
	}
	var live clientStatus
	if json.Unmarshal(reply, &live) != nil || live.Kubeconfig != filepath.Join(s.state, "current", "kubeconfig") {
		return nil, errors.New("invalid helper status")
	}
	return &live, nil
}

// Stopping a session never needs to launch a helper. If no helper owns the
// lock, report any remaining edit using directory metadata alone.
func (s *service) endSession(op string) error {
	if err := checkPrivateDir(s.state); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	conn, err := s.runningConnection(time.Now().Add(statusTimeout))
	if errors.Is(err, errStaleSocket) {
		err = s.stoppedHelper()
	}
	if err != nil {
		return err
	}
	if conn == nil {
		return json.NewEncoder(os.Stdout).Encode(s.status())
	}
	result, err := exchangeRPC(conn, request{Op: op}, time.Now().Add(16*time.Minute))
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func (s *service) inspectStatus() (clientStatus, error) {
	v := clientStatus{FullyLocked: true, Kubeconfig: filepath.Join(s.state, "current", "kubeconfig")}
	if err := checkPrivateDir(s.state); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return v, nil
		}
		v.problem("vault state directory is unsafe or unavailable", "Check the owner and permissions of the vault directory.")
	} else {
		paths, editErr := s.editPaths()
		v.EditPaths = paths
		if len(paths) > 0 {
			v.EditOpen, v.FullyLocked, v.EditPath = true, false, paths[0]
		}
		if editErr != nil {
			v.problem(editErr.Error(), "Inspect the edit directory before changing any vault files.")
		}
		s.inspectGeneration(&v)
		// An older helper may traverse the edit directory. Only ask when safe.
		if editErr == nil {
			live, err := s.liveStatus()
			if err != nil {
				v.problem(err.Error(), "Run kubeconfig-vault serve to diagnose the helper. Press Ctrl-C to exit if it starts.")
			} else if live != nil {
				v.Unlocked, v.ExpiresAt, v.PausedUntil, v.HelperRunning = live.Unlocked, live.ExpiresAt, live.PausedUntil, true
				v.EditOpen, v.EditPaths, v.EditPath = live.EditOpen, live.EditPaths, live.EditPath
				for _, msg := range live.Problems {
					v.problem(msg, "Inspect the edit directory before changing any vault files.")
				}
				v.FullyLocked = len(v.Problems) == 0 && live.FullyLocked && !v.EditOpen && !v.Unlocked
			}
		}
	}
	if len(v.Problems) > 0 {
		if v.EditOpen {
			v.NextAction = "Preserve the plaintext edit before making repairs. " + v.NextAction
		}
		return v, errors.New("vault status degraded")
	}
	return v, nil
}

func (s *service) printStatus(asJSON bool) error {
	state, err := s.inspectStatus()
	if asJSON {
		if e := json.NewEncoder(os.Stdout).Encode(state); e != nil {
			return e
		}
		return err
	}
	switch {
	case err != nil:
		fmt.Fprintln(os.Stdout, "Vault status degraded:", strings.Join(state.Problems, "; "))
	case !state.Configured:
		fmt.Fprintln(os.Stdout, "Not set up — run kubeconfig-vault setup.")
	case state.Unlocked:
		fmt.Fprintln(os.Stdout, "Session unlocked until", state.ExpiresAt)
	default:
		fmt.Fprintln(os.Stdout, "Session locked.")
	}
	if state.PausedUntil != "" {
		fmt.Fprintln(os.Stdout, "Automatic unlock paused until", state.PausedUntil, "— run kubeconfig-vault unlock to retry now.")
	}
	if state.EditOpen {
		fmt.Fprintln(os.Stdout, "Plaintext edit still open:", strings.Join(state.EditPaths, ", "))
	}
	if state.NextAction != "" {
		fmt.Fprintln(os.Stdout, state.NextAction)
	}
	return err
}
