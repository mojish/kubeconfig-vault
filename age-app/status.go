package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const statusTimeout = 2 * time.Second

type clientStatus struct {
	Configured    bool     `json:"configured"`
	HelperRunning bool     `json:"helper_running"`
	Unlocked      bool     `json:"unlocked"`
	FullyLocked   bool     `json:"fully_locked"`
	EditOpen      bool     `json:"edit_open"`
	EditPath      string   `json:"edit_path,omitempty"`
	EditPaths     []string `json:"edit_paths,omitempty"`
	Kubeconfig    string   `json:"kubeconfig"`
	ExpiresAt     string   `json:"expires_at,omitempty"`
}

// Check file metadata only. Authenticated contents are verified during unlock.
func (s *service) configured() (bool, error) {
	id, err := currentID(s.state)
	if err != nil || id == "" {
		return false, err
	}
	generations := filepath.Join(s.state, "generations")
	dir := filepath.Join(generations, id)
	for _, path := range []string{generations, dir} {
		if err := checkPrivateDir(path); err != nil {
			return false, errors.New("active vault generation is missing or unsafe")
		}
	}
	for _, name := range []string{"kubeconfig", "metadata.json", "vault.age"} {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return false, errors.New("active vault generation is incomplete")
		}
	}
	return true, nil
}

// Query a running helper once. A passive status check must never start one.
func (s *service) inspectStatus() (clientStatus, error) {
	offline := clientStatus{FullyLocked: true, Kubeconfig: filepath.Join(s.state, "current", "kubeconfig")}
	if err := checkPrivateDir(s.state); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return offline, nil
		}
		return clientStatus{}, err
	}
	configured, err := s.configured()
	if err != nil {
		return clientStatus{}, err
	}
	offline.Configured = configured
	socket, err := os.Lstat(s.socket())
	if err == nil {
		if socket.Mode()&os.ModeSocket == 0 {
			return clientStatus{}, errors.New("invalid helper socket")
		}
		deadline := time.Now().Add(statusTimeout)
		conn, err := s.connect(deadline)
		if err == nil {
			reply, err := exchangeRPC(conn, request{Op: "status"}, deadline)
			if err != nil {
				return clientStatus{}, err
			}
			var live clientStatus
			if err := json.Unmarshal(reply, &live); err != nil || live.Kubeconfig == "" {
				return clientStatus{}, errors.New("invalid helper status")
			}
			live.Configured, live.HelperRunning = configured, true
			return live, nil
		}
		if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ECONNREFUSED) {
			return clientStatus{}, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return clientStatus{}, err
	}
	offline.EditPaths = s.editPaths()
	if len(offline.EditPaths) > 0 {
		offline.EditPath = offline.EditPaths[0]
		offline.EditOpen, offline.FullyLocked = true, false
	}
	return offline, nil
}

func (s *service) printStatus(asJSON bool) error {
	state, err := s.inspectStatus()
	if err != nil {
		return err
	}
	if asJSON {
		return json.NewEncoder(os.Stdout).Encode(state)
	}
	switch {
	case !state.Configured:
		fmt.Fprintln(os.Stdout, "Not set up — run kubeconfig-vault setup.")
	case state.Unlocked:
		fmt.Fprintln(os.Stdout, "Session unlocked until", state.ExpiresAt)
	default:
		fmt.Fprintln(os.Stdout, "Session locked.")
	}
	if state.EditOpen {
		fmt.Fprintln(os.Stdout, "Plaintext edit still open:", strings.Join(state.EditPaths, ", "))
	}
	return nil
}
