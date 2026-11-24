package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecoverFlagOrder(t *testing.T) {
	dir := privateTemp(t)
	p, key := samplePayload(t)
	cipher, err := encryptPayload(p, key.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	vault, identity := filepath.Join(dir, "vault.age"), filepath.Join(dir, "recovery")
	if err := writeNew(vault, cipher); err != nil {
		t.Fatal(err)
	}
	if err := writeNew(identity, []byte(key.String())); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--check", "--key", identity}, {"--key", identity, "--check"},
		{"--out", filepath.Join(dir, "first"), "--key", identity},
		{"--key", identity, "--out", filepath.Join(dir, "second")},
	} {
		if err := runRecover(append([]string{vault}, args...)); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{
		{"--out", ""}, {"--key", "", "--check"}, {"--key", identity},
		{"--check", "--out", "another"}, {"--out", "first", "--out", "second"},
		{"--check", "--check"}, {"--check", "--unknown"},
	} {
		if err := runRecover(append([]string{vault}, args...)); err == nil || !strings.HasPrefix(err.Error(), "usage:") {
			t.Errorf("expected usage error for %v", args)
		}
	}
}

func TestExportAndRecoverRejectUnavailableOutputs(t *testing.T) {
	dir := privateTemp(t)
	existing := filepath.Join(dir, "existing")
	if err := os.WriteFile(existing, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(dir, "absent"), dangling); err != nil {
		t.Fatal(err)
	}
	s := service{state: filepath.Join(dir, "unused-state")}
	for _, path := range []string{existing, dangling, filepath.Join(dir, "missing", "out")} {
		_, exportErr := s.handle(context.Background(), request{Op: "export", Path: path})
		recoverErr := recoverFile("absent-backup", filepath.Join(dir, "absent-key"), path)
		for _, err := range []error{exportErr, recoverErr} {
			if err == nil || !strings.Contains(err.Error(), "output") {
				t.Errorf("expected an output error before authentication, got %v", err)
			}
		}
	}
	b, err := os.ReadFile(existing)
	if err != nil || string(b) != "keep" {
		t.Fatal("existing output changed")
	}
}

func TestRecoveryPreflightChecksOnlyAgeHeader(t *testing.T) {
	path := filepath.Join(privateTemp(t), "backup.age")
	if err := checkBackupInput(path); err == nil {
		t.Fatal("missing backup passed the preflight")
	}
	for _, contents := range []string{"", "not a vault", ageHeader} {
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		if err := checkBackupInput(path); (err == nil) != (contents == ageHeader) {
			t.Fatalf("unexpected preflight result: %v", err)
		}
	}
}
