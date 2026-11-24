package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func warmSession(t *testing.T) (*service, request, string) {
	t.Helper()
	p, key := samplePayload(t)
	s := &service{state: privateTemp(t), ttl: time.Hour}
	cipher, err := encryptPayload(p, key.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	id, err := commitSnapshot(s.state, "", p, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.cachePayload(0, p, id); err != nil {
		t.Fatal(err)
	}
	req := request{Op: "credential", ID: p.Records["demo"].ID, Cluster: &p.Projection.Clusters[0].Cluster}
	return s, req, filepath.Join(s.state, "generations", id)
}

func BenchmarkWarmCredentialDelivery(b *testing.B) {
	for _, count := range []int{10, 100, 1000} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			p, key := samplePayload(b)
			first := p.Projection.Contexts[0]
			for i := 1; i < count; i++ {
				copy := first
				copy.Name = "context-" + strconv.Itoa(i)
				p.Projection.Contexts = append(p.Projection.Contexts, copy)
			}
			cipher, err := encryptPayload(p, key.Recipient())
			if err != nil {
				b.Fatal(err)
			}
			s := &service{state: privateTemp(b), ttl: time.Hour}
			id, err := commitSnapshot(s.state, "", p, cipher)
			if err != nil {
				b.Fatal(err)
			}
			if err := s.cachePayload(0, p, id); err != nil {
				b.Fatal(err)
			}
			req := request{Op: "credential", ID: p.Records["demo"].ID, Cluster: &p.Projection.Clusters[0].Cluster}
			if _, err := s.handle(context.Background(), req); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				if _, err := s.handle(context.Background(), req); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestWarmCredentialSkipsCiphertextRead(t *testing.T) {
	s, req, dir := warmSession(t)
	vault := filepath.Join(dir, "vault.age")
	old := time.Unix(1000, 0)
	resetAccess := func() {
		t.Helper()
		if err := os.Chtimes(vault, old, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	wasRead := func() bool {
		t.Helper()
		var st unix.Stat_t
		if err := unix.Stat(vault, &st); err != nil {
			t.Fatal(err)
		}
		return !time.Unix(int64(st.Atim.Sec), int64(st.Atim.Nsec)).Equal(old)
	}
	// Establish that access time can distinguish reads on this filesystem.
	resetAccess()
	if _, err := loadSnapshot(s.state); err != nil {
		t.Fatal(err)
	}
	if !wasRead() {
		t.Skip("filesystem does not update access time on read")
	}
	resetAccess()
	if _, err := s.handle(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if wasRead() {
		t.Fatal("warm credential read the ciphertext")
	}
}

func TestMissingVaultDoesNotStartPromptCooldown(t *testing.T) {
	s, req, dir := warmSession(t)
	s.clearSession()
	if err := os.Remove(filepath.Join(dir, "vault.age")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.handle(context.Background(), req); err == nil || !s.retryAfter.IsZero() {
		t.Fatal("missing ciphertext should report a file error without delaying the next attempt")
	}
}

func TestWarmDeliveryRechecksClientBytesAfterNamespaceChange(t *testing.T) {
	s, req, dir := warmSession(t)
	if _, err := s.handle(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "kubeconfig")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	client, err := parseConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	client.Contexts[0].Context.Namespace = "new-namespace"
	selection, err := serializeConfig(client)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, selection, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.handle(context.Background(), req); err != nil {
		t.Fatal("a namespace change should preserve the session", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.Replace(selection, []byte("example.invalid"), []byte("changed.invalid"), 1)
	if bytes.Equal(changed, selection) || len(changed) != len(selection) {
		t.Fatal("fixture must change the API endpoint without changing the length")
	}
	if err := os.WriteFile(path, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if result, err := s.handle(context.Background(), req); err == nil || result != nil || s.cache != nil {
		t.Fatal("a changed connection with unchanged size and mtime must invalidate the session")
	}
}

func TestColdStaleRequestLeavesVaultLocked(t *testing.T) {
	s, req, _ := warmSession(t)
	s.clearSession()
	s.browser = filepath.Join(t.TempDir(), "unused-browser")
	stale := *req.Cluster
	stale.TLSName = "previous.example.invalid"
	for _, old := range []request{
		{Op: "credential", ID: randomID(), Cluster: req.Cluster},
		{Op: "credential", ID: req.ID, Cluster: &stale},
	} {
		result, err := s.handle(context.Background(), old)
		if !errors.Is(err, errCredentialBinding) || result != nil || s.cache != nil || !s.retryAfter.IsZero() {
			t.Fatalf("stale client should fail before authentication: %v", err)
		}
	}
}

func TestCredentialReferenceUsesUserAndClusterTogether(t *testing.T) {
	p, _ := samplePayload(t)
	c := p.Projection
	id := p.Records["demo"].ID
	first := c.Clusters[0]
	second := namedCluster{Name: "second", Cluster: cluster{Server: "https://second.invalid"}}
	c.Clusters = append(c.Clusters, second)
	c.Contexts = append(c.Contexts, namedContext{Name: "other", Context: contextConfig{User: "other", Cluster: second.Name}})
	if !c.referencesCredential(id, first.Cluster) || c.referencesCredential(id, second.Cluster) {
		t.Fatal("reference must match the cluster and user in the same context")
	}
	c.Clusters = append(c.Clusters, namedCluster{Name: "alias", Cluster: first.Cluster})
	c.Contexts[0].Context.Cluster = "alias"
	if !c.referencesCredential(id, first.Cluster) {
		t.Fatal("equivalent cluster settings under an alias should still match")
	}
}

func TestWarmCredentialRejectsChangedState(t *testing.T) {
	tests := map[string]func(string, *service) error{
		"changed metadata": func(dir string, s *service) error {
			meta := s.cache.Meta
			meta.Identity += "changed"
			data, err := json.Marshal(meta)
			if err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(dir, "metadata.json"), data, 0600)
		},
		"changed cluster": func(dir string, _ *service) error {
			path := filepath.Join(dir, "kubeconfig")
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(path, bytes.ReplaceAll(data, []byte("example.invalid"), []byte("changed.invalid")), 0600)
		},
		"different current generation": func(_ string, s *service) error {
			path := filepath.Join(s.state, "current")
			if err := os.Remove(path); err != nil {
				return err
			}
			return os.Symlink("generations/"+randomID(), path)
		},
		"missing vault": func(dir string, _ *service) error {
			return os.Remove(filepath.Join(dir, "vault.age"))
		},
		"oversized vault": func(dir string, _ *service) error {
			return os.Truncate(filepath.Join(dir, "vault.age"), maxVault+1)
		},
		"public vault": func(dir string, _ *service) error {
			return os.Chmod(filepath.Join(dir, "vault.age"), 0644)
		},
		"hardlinked vault": func(dir string, _ *service) error {
			return os.Link(filepath.Join(dir, "vault.age"), filepath.Join(dir, "other"))
		},
		"symlinked vault": func(dir string, _ *service) error {
			path := filepath.Join(dir, "vault.age")
			if err := os.Rename(path, path+".old"); err != nil {
				return err
			}
			return os.Symlink(path+".old", path)
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			s, req, dir := warmSession(t)
			if _, err := s.handle(context.Background(), req); err != nil {
				t.Fatal(err)
			}
			if err := change(dir, s); err != nil {
				t.Fatal(err)
			}
			if result, err := s.handle(context.Background(), req); err == nil || result != nil {
				t.Fatal("returned a credential from changed state")
			}
			if s.cache != nil {
				t.Fatal("invalid generation kept its cached session")
			}
		})
	}
}
