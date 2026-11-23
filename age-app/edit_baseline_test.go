package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// Build a private synthetic vault and establish the proof from the payload
// read back through its recovery recipient. Browser tests cover config-unlock.
func fixtureOpenEdit(t *testing.T, withCA bool) (*service, *snapshot, []byte) {
	t.Helper()
	s := &service{state: privateTemp(t), executable: "/synthetic/helper"}
	source := synthetic
	if withCA {
		cert, _ := auditCertificate(t)
		if err := writeNew(filepath.Join(s.state, "ca.pem"), cert); err != nil {
			t.Fatal(err)
		}
		source = strings.Replace(source, "    server:", "    certificate-authority: ca.pem\n    server:", 1)
	}
	input := []byte(source)
	p, err := prepare(input, s.state, s.state, s.executable, nil)
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	p.Meta = metadata{1, "AGE-PLUGIN-FIDO2PRF-1synthetic", recovery.Recipient().String()}
	cipher, err := encryptPayload(p, &auditRecipient{})
	if err != nil {
		t.Fatal(err)
	}
	id, err := commitSnapshot(s.state, "", p, cipher)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := loadSnapshot(s.state)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := decryptPayload(snap.Cipher, recovery)
	if err != nil {
		t.Fatal(err)
	}
	s.edit = authenticatedEdit(verified, snap)
	if err = privateDir(filepath.Dir(s.editPath())); err != nil {
		t.Fatal(err)
	}
	if err = writeNew(s.editPath(), input); err != nil {
		t.Fatal(err)
	}
	if err = writeNew(filepath.Join(s.state, "edit", "generation"), []byte(id)); err != nil {
		t.Fatal(err)
	}
	return s, snap, input
}

func TestCloseUnchangedEditRetainsGenerationAndSelections(t *testing.T) {
	s, snap, _ := fixtureOpenEdit(t, true)
	snap.Projection.Contexts[0].Context.Namespace = "new-selection"
	data, err := serializeConfig(snap.Projection)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(s.state, "current", "kubeconfig"), data, 0600); err != nil {
		t.Fatal(err)
	}
	s.cache = &session{Deadline: time.Now().Add(time.Minute), WallDeadline: time.Now().Add(time.Minute)}
	res, err := s.handle(context.Background(), request{Op: "config-lock"})
	if err != nil {
		t.Fatal(err)
	}
	status := res.(map[string]any)
	if status["changed"] != false || status["fully_locked"] != true || s.edit != nil {
		t.Fatal("unchanged close did not clear edit and credentials")
	}
	after, err := loadSnapshot(s.state)
	if err != nil || after.ID != snap.ID || after.Projection.Contexts[0].Context.Namespace != "new-selection" {
		t.Fatal("unchanged close altered generation or client selections")
	}
	if _, err := os.Lstat(filepath.Join(s.state, "edit", "generation")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("edit marker remains")
	}
}

func TestUnchangedEditRequiresAuthenticatedInputs(t *testing.T) {
	s, _, input := fixtureOpenEdit(t, true)
	for _, kind := range []string{"source", "generation", "ciphertext", "metadata", "public projection", "relocated command"} {
		t.Run(kind, func(t *testing.T) {
			snap, err := loadSnapshot(s.state)
			if err != nil {
				t.Fatal(err)
			}
			candidate := input
			switch kind {
			case "source":
				candidate = append([]byte("# edited\n"), input...)
			case "generation":
				snap.ID = randomID()
			case "ciphertext":
				snap.Cipher[0] ^= 1
			case "metadata":
				snap.Meta.Identity += "changed"
			case "public projection":
				snap.Projection.Clusters[0].Cluster.Server = "https://changed.invalid"
			case "relocated command":
				old := s.executable
				s.executable = filepath.Join(s.state, commandName)
				t.Cleanup(func() { s.executable = old })
			}
			if s.unchangedEdit(candidate, snap) {
				t.Fatal("accepted mismatched edit")
			}
		})
	}
	snap, err := loadSnapshot(s.state)
	if err != nil {
		t.Fatal(err)
	}
	newCA, _ := auditCertificate(t)
	if err = os.WriteFile(filepath.Join(s.state, "ca.pem"), newCA, 0600); err != nil {
		t.Fatal(err)
	}
	if s.unchangedEdit(input, snap) {
		t.Fatal("accepted changed external CA")
	}
}

func TestCancelledUnchangedClosePreservesEdit(t *testing.T) {
	s, _, input := fixtureOpenEdit(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.saveEdit(ctx, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected error: %v", err)
	}
	data, err := readBounded(s.editPath(), maxSource, true)
	if err != nil || string(data) != string(input) {
		t.Fatal("lost plaintext on cancellation")
	}
}

func TestLockInvalidatesEditProof(t *testing.T) {
	s, snap, input := fixtureOpenEdit(t, false)
	if !s.unchangedEdit(input, snap) {
		t.Fatal("initial proof missing")
	}
	if status := s.lock(false); status["edit_open"] != true {
		t.Fatal("lost edit during lock")
	}
	if s.unchangedEdit(input, snap) {
		t.Fatal("accepted edit proof after locking")
	}
	if _, err := s.handle(context.Background(), request{Op: "config-discard"}); err != nil {
		t.Fatal(err)
	}
}

func TestEditCleanupReportsDirectorySyncFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires ordinary Unix directory permissions")
	}
	for _, op := range []string{"config-lock", "config-discard"} {
		t.Run(op, func(t *testing.T) {
			s, _, _ := fixtureOpenEdit(t, false)
			dir := filepath.Dir(s.editPath())
			// Permit unlink and lookup by name while denying the directory open
			// required by fsync.
			if err := os.Chmod(dir, 0300); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0700) })
			_, err := s.handle(context.Background(), request{Op: op})
			if err == nil || !strings.Contains(err.Error(), "make edit cleanup durable") {
				t.Fatalf("expected directory sync failure, got %v", err)
			}
			for _, path := range []string{s.editPath(), s.pendingEditPath(), filepath.Join(dir, "generation")} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("expected cleanup of %s before sync: %v", path, err)
				}
			}
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			result, err := s.handle(context.Background(), request{Op: "config-discard"})
			if err != nil || result.(map[string]any)["fully_locked"] != true {
				t.Fatalf("retry did not finish cleanup: %v", err)
			}
		})
	}
}

func TestDiscardWithoutEditDirectory(t *testing.T) {
	s := service{state: privateTemp(t)}
	if _, err := s.handle(context.Background(), request{Op: "config-discard"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Dir(s.editPath())); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("discard created an edit directory")
	}
}
