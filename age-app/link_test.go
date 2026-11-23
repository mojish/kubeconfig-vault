package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientEntryPreservesAliasesAndStopsAtManagedLink(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "vault")
	if err := privateDir(state); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "config")
	entry := filepath.Join(dir, "original")
	if err := os.WriteFile(entry, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("original", config); err != nil {
		t.Fatal(err)
	}
	if got, err := clientEntry(state, config); err != nil || got != entry {
		t.Fatalf("alias %q: %v", got, err)
	}
	if err := replaceClient(entry, "", filepath.Join(state, "current", "kubeconfig")); err != nil {
		t.Fatal(err)
	}
	if got, err := clientEntry(state, config); err != nil || got != entry {
		t.Fatalf("managed alias %q: %v", got, err)
	}
	if _, err := clientEntry(state, filepath.Join(state, "test")); err == nil {
		t.Fatal("accepted state file")
	}
}
func TestSetupPathMergeRequiresSelection(t *testing.T) {
	t.Setenv("KUBECONFIG", "a:b")
	if _, err := setupPath(nil); err == nil {
		t.Fatal("accepted merged config")
	}
	if _, err := setupPath([]string{"a"}); err != nil {
		t.Fatal(err)
	}
}
func TestLegacyUnlink(t *testing.T) {
	dir := t.TempDir()
	s := service{state: dir}
	client := filepath.Join(t.TempDir(), "config")
	if err := os.Symlink(filepath.Join(dir, "current", "kubeconfig"), client); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(client+configBackupSuffix, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.clientLink("unlink", []string{"--kubeconfig", client}); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(client); err != nil || string(b) != "original" {
		t.Fatal("original was not restored")
	}
}

func TestFreshSetupLostRaceRejectsUnenrolledKey(t *testing.T) {
	state := privateTemp(t)
	path := filepath.Join(t.TempDir(), "client")
	if err := os.Symlink("generations/00112233445566778899aabbccddeeff", filepath.Join(state, "current")); err != nil {
		t.Fatal(err)
	}
	s := service{state: state}
	_, err := s.setup(context.Background(), request{Path: path, RecoveryIdentity: []byte("synthetic new identity")})
	if err == nil || !strings.Contains(err.Error(), "not enrolled") {
		t.Fatalf("expected a recovery-key conflict: %v", err)
	}
}

func TestAliasConfigWriterBlocksActivation(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	alias, entry := filepath.Join(dir, "alias"), filepath.Join(dir, "entry")
	if err := os.Symlink(entry, alias); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(alias+".lock", nil, 0600); err != nil {
		t.Fatal(err)
	}
	err = withClientLocks(alias, entry, func() error { t.Fatal("modified locked alias"); return nil })
	if err == nil {
		t.Fatal("expected contention")
	}
	if _, err := os.Stat(entry + ".lock"); !os.IsNotExist(err) {
		t.Fatal("target lock leaked")
	}
}
func TestPublishNewNeverReplacesFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "backup")
	if err := publishNew(file, []byte("original")); err != nil {
		t.Fatal(err)
	}
	if err := publishNew(file, []byte("other")); err == nil {
		t.Fatal("replaced backup")
	}
	b, err := os.ReadFile(file)
	if err != nil || string(b) != "original" {
		t.Fatal("backup changed")
	}
}
