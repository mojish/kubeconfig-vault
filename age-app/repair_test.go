package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestAutomaticUnlockPause(t *testing.T) {
	now := time.Unix(500, 0)
	for _, tc := range []struct {
		err  error
		wait time.Duration
	}{
		{errRequestDeclined, 10 * time.Minute}, {errors.New("device failure"), 30 * time.Second},
	} {
		until := retryDeadline(now, tc.err)
		if until.Sub(now) != tc.wait || automaticPause(until.Add(-time.Nanosecond), until) == nil || automaticPause(until, until) != nil {
			t.Fatal("wrong retry boundary")
		}
	}
	fresh := service{state: privateTemp(t)}
	if _, ok := fresh.status()["automatic_unlock_paused_until"]; ok {
		t.Fatal("new helper inherited a pause")
	}
}

func TestRepairProjection(t *testing.T) {
	s := service{state: "/synthetic/state", executable: "/synthetic/helper"}
	for _, tc := range []struct {
		name string
		edit func(*payload)
	}{
		{"proxy query", func(p *payload) { p.Portable.Clusters[0].Cluster.Proxy = "https://example.invalid/?sensitive" }},
		{"external CA", func(p *payload) { p.Portable.Clusters[0].Cluster.CAFile = "absent" }},
		{"unknown command", func(p *payload) { p.Projection.Users[0].User.Exec.Command = "/untrusted" }},
		{"inline token", func(p *payload) { p.Projection.Users[0].User.Token = "synthetic" }},
		{"changed cluster binding", func(p *payload) { p.Records["demo"] = record{ID: p.Records["demo"].ID, Token: "synthetic"} }},
		{"unknown credential ID", func(p *payload) { p.Projection.Users[0].User.Exec.Args[3] = randomID() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := samplePayload(t)
			tc.edit(p)
			if data, err := s.repairedConfig(p); err == nil || len(data) != 0 {
				t.Fatal("published inconsistent settings")
			}
		})
	}
	p, _ := samplePayload(t)
	p.Projection.Preferences = map[string]any{"opaque": "sensitive-value"}
	data, err := s.repairedConfig(p)
	if err != nil || bytes.Contains(data, []byte("sensitive-value")) || bytes.Contains(data, []byte(p.Records["demo"].Token)) {
		t.Fatal("invalid repaired config", err)
	}
}

func TestRepairRechecksBeforePublication(t *testing.T) {
	for _, operation := range []string{"cancel", "client replacement", "identical new link", "identical new alias", "changed generation", "changed ciphertext", "open edit", "competing destination", "unsafe destination", "success"} {
		t.Run(operation, func(t *testing.T) {
			s := service{state: privateTemp(t)}
			client := filepath.Join(privateTemp(t), "client")
			dest := filepath.Join(s.state, "current", "kubeconfig")
			p, _ := samplePayload(t)
			id, err := commitSnapshot(s.state, "", p, []byte("synthetic encrypted fixture"))
			if err != nil {
				t.Fatal(err)
			}
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			must(os.Symlink(dest, client))
			must(os.Remove(dest))
			if operation == "identical new alias" {
				alias := filepath.Join(filepath.Dir(client), "alias")
				must(os.Symlink(client, alias))
				client = alias
			}
			target, err := s.selectRepair(client)
			must(err)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch operation {
			case "cancel":
				cancel()
			case "client replacement":
				must(os.Remove(client))
				must(os.WriteFile(client, []byte("user file"), 0600))
			case "identical new alias":
				must(os.Symlink(target.entry, client+".new"))
				must(os.Rename(client+".new", client))
			case "identical new link":
				must(os.Symlink(dest, client+".new"))
				must(os.Rename(client+".new", client))
			case "changed generation":
				_, err := commitSnapshot(s.state, id, p, []byte("another fixture"))
				must(err)
				must(os.Remove(dest))
			case "changed ciphertext":
				must(os.WriteFile(filepath.Join(s.state, "current", "vault.age"), []byte("different fixture"), 0600))
			case "open edit":
				must(privateDir(filepath.Dir(s.editPath())))
				must(writeNew(s.pendingEditPath(), []byte("preserved")))
			case "competing destination":
				must(writeNew(dest, []byte("existing")))
			case "unsafe destination":
				must(os.Symlink(client, dest))
			}
			err = s.publishRepair(ctx, client, target, []byte("complete file"))
			if operation == "success" {
				must(err)
				cancel() // interruption after publication leaves the complete file in place
				got, err := os.ReadFile(dest)
				must(err)
				if string(got) != "complete file" {
					t.Fatal("partial output")
				}
				if _, err := s.selectRepair(client); err == nil {
					t.Fatal("retry would replace output")
				}
				return
			}
			if err == nil {
				t.Fatal("repair succeeded unexpectedly")
			}
			switch operation {
			case "competing destination":
				got, err := os.ReadFile(dest)
				must(err)
				if string(got) != "existing" {
					t.Fatal("replaced competing file")
				}
			case "unsafe destination":
				got, err := os.Readlink(dest)
				must(err)
				if got != client {
					t.Fatal("replaced symlink")
				}
			default:
				if _, err := os.Lstat(dest); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("published unexpectedly")
				}
			}
		})
	}
}

func TestDegradedStatusPreservesKnownEdits(t *testing.T) {
	for _, name := range []string{"kubeconfig", "metadata.json", "vault.age", "socket", "edit symlink", "staging interrupted", "unreadable"} {
		t.Run(name, func(t *testing.T) {
			s := service{state: privateTemp(t)}
			p, _ := samplePayload(t)
			_, err := commitSnapshot(s.state, "", p, []byte("fixture"))
			if err != nil {
				t.Fatal(err)
			}
			edit := filepath.Dir(s.editPath())
			if name == "edit symlink" {
				outside := privateTemp(t)
				if err := writeNew(filepath.Join(outside, "kubeconfig"), []byte("external")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, edit); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := privateDir(edit); err != nil {
					t.Fatal(err)
				}
				if err := writeNew(s.pendingEditPath(), []byte("fixture")); err != nil {
					t.Fatal(err)
				}
				if name == "unreadable" {
					err = os.Chmod(filepath.Join(s.state, "current", "vault.age"), 0200)
				} else if name == "socket" {
					err = writeNew(s.socket(), nil)
				} else {
					missing := name
					if name == "staging interrupted" {
						missing = "kubeconfig"
						err = writeNew(s.editPath(), nil)
						if err != nil {
							t.Fatal(err)
						}
					}
					err = os.Remove(filepath.Join(s.state, "current", missing))
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			status, err := s.inspectStatus()
			if err == nil || len(status.Problems) == 0 || status.NextAction == "" || status.FullyLocked {
				t.Fatalf("incomplete diagnosis: %+v", status)
			}
			if name == "edit symlink" {
				if len(status.EditPaths) != 0 || status.EditOpen {
					t.Fatal("followed unsafe directory")
				}
				return
			}
			if !status.EditOpen || !strings.Contains(strings.Join(status.EditPaths, " "), s.pendingEditPath()) {
				t.Fatal("lost plaintext edit location")
			}
			if name == "staging interrupted" && len(status.EditPaths) != 2 {
				t.Fatal("lost one of two plaintext paths")
			}
		})
	}
}

func TestRepairPublicationInterruption(t *testing.T) {
	// Exit without running defers to exercise both sides of the exclusive rename.
	if phase := os.Getenv("KCV_TEST_PUBLICATION_PHASE"); phase != "" {
		dest := os.Getenv("KCV_TEST_PUBLICATION_DEST")
		if err := publishNewChecked(dest, []byte("complete projection"), func() error {
			if phase == "before" {
				os.Exit(23)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		os.Exit(23)
	}
	for _, phase := range []string{"before", "after"} {
		t.Run(phase, func(t *testing.T) {
			dir := privateTemp(t)
			dest := filepath.Join(dir, "kubeconfig")
			cmd := exec.Command(os.Args[0], "-test.run=^TestRepairPublicationInterruption$")
			cmd.Env = append(os.Environ(), "KCV_TEST_PUBLICATION_PHASE="+phase, "KCV_TEST_PUBLICATION_DEST="+dest)
			var exit *exec.ExitError
			if err := cmd.Run(); !errors.As(err, &exit) || exit.ExitCode() != 23 {
				t.Fatalf("child interruption failed: %v", err)
			}
			data, err := os.ReadFile(dest)
			if phase == "before" {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatal("published before rename")
				}
				if err := publishNew(dest, []byte("retry")); err != nil {
					t.Fatal(err)
				}
			} else if err != nil || string(data) != "complete projection" {
				t.Fatal("incomplete published file", err)
			}
		})
	}
}

func TestMissingSocketWithHeldLockIsDegraded(t *testing.T) {
	s := service{state: privateTemp(t)}
	f, err := os.OpenFile(filepath.Join(s.state, "daemon.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if v, err := s.inspectStatus(); err == nil || v.FullyLocked {
		t.Fatal("missing socket concealed helper session")
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if v, err := s.inspectStatus(); err != nil || !v.FullyLocked {
		t.Fatal("stopped helper was not recognized", err)
	}
}
