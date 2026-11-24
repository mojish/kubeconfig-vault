package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPassiveStatusAbsentVault(t *testing.T) {
	// This path also exceeds the Unix socket address limit.
	path := filepath.Join(t.TempDir(), strings.Repeat("a", 110))
	s := service{state: path}
	got, err := s.inspectStatus()
	if err != nil || got.Configured || got.HelperRunning || !got.FullyLocked {
		t.Fatalf("status %+v, error %v", got, err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("status created state")
	}
}

func TestEndSessionBeforeSetupCreatesNothing(t *testing.T) {
	state := filepath.Join(t.TempDir(), "new")
	for _, op := range []string{"lock", "stop"} {
		if err := run([]string{"--state-dir", state, op}); err != nil {
			t.Fatalf("%s before setup: %v", op, err)
		}
		if _, err := os.Lstat(state); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s created vault state: %v", op, err)
		}
	}
}

func TestPassiveStatusGenerationAndOpenEdit(t *testing.T) {
	s := service{state: t.TempDir()}
	if err := os.Chmod(s.state, 0700); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	gen := filepath.Join("generations", id)
	if err := os.MkdirAll(filepath.Join(s.state, gen), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(gen, filepath.Join(s.state, "current")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"metadata.json", "kubeconfig", "vault.age"} {
		if _, err := s.inspectStatus(); err == nil {
			t.Fatal("accepted incomplete generation", name)
		}
		if err := os.WriteFile(filepath.Join(s.state, gen, name), []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(s.editPath()), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.editPath(), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := s.inspectStatus()
	if err != nil || !got.Configured || got.HelperRunning || got.FullyLocked || got.EditPath != s.editPath() {
		t.Fatalf("status %+v, error %v", got, err)
	}
	if err := os.WriteFile(s.socket(), []byte("wrong type"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.inspectStatus(); err == nil {
		t.Fatal("unexpected socket entry accepted")
	}
}

func TestPassiveStatusLiveHelper(t *testing.T) {
	root, err := os.MkdirTemp("", "kcv-st-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	s := service{state: root}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.socket(), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	// An edit is being closed. The RPC supplies the authoritative state.
	if err := os.MkdirAll(filepath.Dir(s.editPath()), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.editPath(), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptUnix()
		if err == nil {
			defer conn.Close()
			var r request
			err = json.NewDecoder(conn).Decode(&r)
			if err == nil && r.Op != "status" {
				err = errors.New("unexpected RPC")
			}
			if err == nil {
				err = json.NewEncoder(conn).Encode(response{Result: clientStatus{Kubeconfig: filepath.Join(s.state, "current", "kubeconfig"), FullyLocked: true}})
			}
		}
		done <- err
	}()
	got, err := s.inspectStatus()
	if err != nil || !got.HelperRunning || got.EditOpen || len(got.EditPaths) != 0 || !got.FullyLocked {
		t.Fatalf("status %+v, error %v", got, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	// A connected peer that sends no response should fail promptly.
	start := time.Now()
	_, err = s.inspectStatus()
	if err == nil || time.Since(start) > statusTimeout+5*time.Second {
		t.Fatal("unresponsive helper exceeded its status timeout", err)
	}
}
