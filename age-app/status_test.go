package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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

func TestBeforeSetupRejectsInvalidCommandsWithoutCreatingState(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "kcv-start-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	state := filepath.Join(dir, "missing")
	for _, args := range [][]string{{"unknown"}, {"backup"}, {"config", "bogus"}, {"unlock"}, {"config", "discard"}} {
		err := run(append([]string{"--state-dir", state}, args...))
		if args[len(args)-1] == "discard" {
			if err != nil {
				t.Fatal(err)
			}
		} else if err == nil {
			t.Fatalf("%v unexpectedly succeeded", args)
		}
		if _, err := os.Lstat(state); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%v created state before setup", args)
		}
	}
}

func TestEnrollmentRejectsLongSocketPathBeforeRecovery(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, strings.Repeat("s", len(unix.RawSockaddrUnix{}.Path)))
	source := filepath.Join(dir, "fixture")
	if err := os.WriteFile(source, []byte(synthetic), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--state-dir", state, "setup", "--check", source}); err != nil {
		t.Fatalf("offline input check needed a socket: %v", err)
	}
	for _, args := range [][]string{{"setup", source}, {"import", source}, {"restore", "unused.age"}, {"serve"}} {
		err := run(append([]string{"--state-dir", state}, args...))
		if err == nil || !strings.Contains(err.Error(), "shorter private directory") {
			t.Fatalf("%v: got %v", args, err)
		}
	}
	if _, err := os.Lstat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unusable state directory was created")
	}
}

func TestRPCIgnoresUnexpectedSocketEntry(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "kcv-sock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	s := service{state: dir, executable: filepath.Join(dir, "absent")}
	target := filepath.Join(dir, "fixture")
	if err := os.WriteFile(target, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, s.socket()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.rpc(request{Op: "unlock"}); err == nil || !strings.Contains(err.Error(), "invalid helper socket") {
		t.Fatalf("expected a socket diagnostic, got %v", err)
	}
	if got, err := os.Readlink(s.socket()); err != nil || got != target {
		t.Fatal("unexpected socket entry was modified")
	}
}

func TestEndSessionWithAbandonedSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "kcv-st-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	s := service{state: dir}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.socket(), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.endSession("lock"); err != nil {
		t.Fatal(err)
	}
	got, err := s.inspectStatus()
	if err != nil || got.HelperRunning || !got.FullyLocked {
		t.Fatalf("abandoned socket should report a stopped helper: %+v, %v", got, err)
	}
	if info, err := os.Lstat(s.socket()); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatal("status changed the abandoned socket")
	}
	lock, err := os.OpenFile(filepath.Join(dir, "daemon.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := s.endSession("stop"); err == nil {
		t.Fatal("reported a stopped session while its daemon lock was held")
	}
	if got, err := s.inspectStatus(); err == nil || got.FullyLocked {
		t.Fatal("claimed a fully locked vault while its helper lock was held")
	}
}

func TestConcurrentStops(t *testing.T) {
	s := service{state: privateTemp(t), stop: make(chan struct{})}
	var callers sync.WaitGroup
	for range 8 {
		callers.Go(func() {
			if _, err := s.handle(context.Background(), request{Op: "stop"}); err != nil {
				t.Error(err)
			}
		})
	}
	callers.Wait()
	select {
	case <-s.stop:
	case <-time.After(time.Second):
		t.Fatal("helper did not receive its stop signal")
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
