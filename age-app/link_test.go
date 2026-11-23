package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigLinkRoundTrip(t *testing.T) {
	for _, kind := range []string{"regular", "relative symlink", "absent"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config")
			backup := path + configBackupSuffix
			generated := filepath.Join(dir, "vault-client-config")
			if err := os.WriteFile(generated, []byte("generated client config"), 0600); err != nil {
				t.Fatal(err)
			}
			const original = "synthetic original in its original formatting\n"
			switch kind {
			case "regular":
				if err := os.WriteFile(path, []byte(original), 0644); err != nil {
					t.Fatal(err)
				}
			case "relative symlink":
				if err := os.WriteFile(filepath.Join(dir, "original"), []byte(original), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("original", path); err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 2; i++ {
				if err := changeConfigLink(path, generated, true); err != nil {
					t.Fatal(err)
				}
			}
			if target, err := os.Readlink(path); err != nil || target != generated {
				t.Fatal("expected a symlink to the generated kubeconfig")
			}
			if kind == "regular" {
				info, err := os.Stat(backup)
				if err != nil || info.Mode().Perm() != 0600 {
					t.Fatal("plaintext backup is not private")
				}
			}
			if err := changeConfigLink(path, generated, false); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(backup); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("backup remains after unlink")
			}
			if kind == "absent" {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("unlink did not remove a link without an original")
				}
				return
			}
			if data, err := os.ReadFile(path); err != nil || string(data) != original {
				t.Fatal("unlink did not restore the original config")
			}
			if kind == "relative symlink" {
				if target, err := os.Readlink(path); err != nil || target != "original" {
					t.Fatal("unlink did not restore the original relative symlink")
				}
			}
		})
	}
}

func TestConfigLinkLeavesUnrelatedEntriesAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	backup := path + configBackupSuffix
	generated := filepath.Join(dir, "vault-client-config")
	if err := os.Symlink("unrelated", path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup, []byte("existing unrelated backup"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, link := range []bool{true, false} {
		if err := changeConfigLink(path, generated, link); err == nil {
			t.Fatal("operation accepted an unrelated entry or existing backup")
		}
		if target, err := os.Readlink(path); err != nil || target != "unrelated" {
			t.Fatal("unrelated config changed")
		}
		if data, err := os.ReadFile(backup); err != nil || string(data) != "existing unrelated backup" {
			t.Fatal("existing backup changed")
		}
	}
}
