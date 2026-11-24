package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnlinkRollbackStates(t *testing.T) {
	const digest = "01234567890123456789012345678901"
	for _, tc := range []struct {
		name, entry, receipt string
		legacy, sealed       bool
		wantError            string
	}{
		{"confirmed absent original", "link", noOriginalReceipt, false, false, ""},
		{"interrupted link or unlink", "", noOriginalReceipt, false, false, ""},
		{"legacy link without backup", "link", "", false, false, "both missing"},
		{"malformed receipt", "link", "invalid", false, false, "invalid rollback receipt"},
		{"missing ciphertext", "link", digest, true, false, "encrypted rollback is missing"},
		{"ciphertext without receipt", "link", "", false, true, "no receipt"},
		{"conflicting legacy backup", "link", noOriginalReceipt, true, false, "conflicts"},
		{"conflicting encrypted backup", "link", noOriginalReceipt, false, true, "conflicts"},
		{"replacement client", "new client", noOriginalReceipt, false, false, "not linked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(privateTemp(t))
			if err != nil {
				t.Fatal(err)
			}
			s := service{state: privateTemp(t)}
			entry := filepath.Join(dir, "config")
			originals := map[string]string{}
			if tc.entry == "link" {
				if err := os.Symlink(filepath.Join(s.state, "current", "kubeconfig"), entry); err != nil {
					t.Fatal(err)
				}
			} else if tc.entry != "" {
				originals[entry] = tc.entry
			}
			if tc.receipt != "" {
				originals[s.receipt(entry)] = tc.receipt
			}
			if tc.legacy {
				originals[entry+configBackupSuffix] = "synthetic original"
			}
			if tc.sealed {
				originals[entry+sealedSuffix] = "synthetic backup"
			}
			for path, data := range originals {
				if err := os.WriteFile(path, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			err = s.clientLink("unlink", []string{"--kubeconfig", entry})
			if tc.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
				for _, path := range []string{entry, s.receipt(entry)} {
					if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("expected %s to be absent: %v", path, err)
					}
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("expected %q, got %v", tc.wantError, err)
			}
			if tc.entry == "link" && !s.isLinked(entry) {
				t.Fatal("lost managed link")
			}
			for path, want := range originals {
				if data, err := os.ReadFile(path); err != nil || string(data) != want {
					t.Fatalf("changed %s", path)
				}
			}
		})
	}
}

func TestRestoreMissingLegacyBackupPreservesLink(t *testing.T) {
	entry := filepath.Join(t.TempDir(), "config")
	if err := os.Symlink("managed", entry); err != nil {
		t.Fatal(err)
	}
	if err := restoreLegacyConfigLink(entry); err == nil {
		t.Fatal("accepted missing legacy backup")
	}
	if target, err := os.Readlink(entry); err != nil || target != "managed" {
		t.Fatal("lost managed link")
	}
}

func TestInterruptedUnlinkPreservesAmbiguousState(t *testing.T) {
	for _, tc := range []struct {
		name, marker, extra, want string
		cancel                    bool
	}{
		{"wrong length", "short", "", "invalid completion receipt", false},
		{"two receipts", strings.Repeat("x", 32), "receipt", "conflicting", false},
		{"writer lock", strings.Repeat("x", 32), "lock", "locked", false},
		{"legacy backup", strings.Repeat("x", 32), "legacy", "rollback state changed", false},
		{"cancelled", strings.Repeat("x", 32), "", "canceled", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(privateTemp(t))
			if err != nil {
				t.Fatal(err)
			}
			entry := filepath.Join(dir, "client")
			s := service{state: privateTemp(t)}
			marker := s.receipt(entry) + ".restored"
			files := map[string]string{entry: "synthetic client", marker: tc.marker}
			switch tc.extra {
			case "receipt":
				files[s.receipt(entry)] = strings.Repeat("r", 32)
			case "lock":
				files[entry+".lock"] = ""
			case "legacy":
				files[entry+configBackupSuffix] = "synthetic backup"
			}
			for name, data := range files {
				if err := os.WriteFile(name, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			if _, err := s.undoSetup(ctx, entry); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
			for name, data := range files {
				got, err := os.ReadFile(name)
				if err != nil || string(got) != data {
					t.Fatalf("failed to preserve %s", filepath.Base(name))
				}
			}
		})
	}
}

func TestSetupExplainsInterruptedNoOriginalAttachment(t *testing.T) {
	dir, err := filepath.EvalSymlinks(privateTemp(t))
	if err != nil {
		t.Fatal(err)
	}
	s := service{state: privateTemp(t)}
	entry := filepath.Join(dir, "config")
	if err := os.Symlink("generations/00112233445566778899aabbccddeeff", filepath.Join(s.state, "current")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.receipt(entry), []byte(noOriginalReceipt), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = s.setup(context.Background(), request{Path: entry})
	if err == nil || !strings.Contains(err.Error(), "config link") || !strings.Contains(err.Error(), "config unlink") {
		t.Fatalf("expected recovery instructions: %v", err)
	}
	if _, err := os.Lstat(entry); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("setup changed interrupted entry")
	}
}
