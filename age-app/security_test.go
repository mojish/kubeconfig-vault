package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

const synthetic = `apiVersion: v1
kind: Config
clusters:
- name: demo
  cluster:
    server: https://example.invalid
users:
- name: demo
  user:
    token: SYNTHETIC-NOT-A-REAL-TOKEN
contexts:
- name: demo
  context:
    cluster: demo
    user: demo
current-context: demo
`

func samplePayload(t *testing.T) (*payload, *age.HybridIdentity) {
	t.Helper()
	p, e := prepare([]byte(synthetic), t.TempDir(), "/synthetic/state", "/synthetic/helper", nil)
	if e != nil {
		t.Fatal(e)
	}
	k, e := age.GenerateHybridIdentity()
	if e != nil {
		t.Fatal(e)
	}
	p.Meta = metadata{1, "AGE-PLUGIN-FIDO2PRF-1synthetic", k.Recipient().String()}
	return p, k
}
func privateTemp(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	if e := os.Chmod(p, 0700); e != nil {
		t.Fatal(e)
	}
	return p
}

func TestConfigBoundary(t *testing.T) {
	for name, data := range map[string]string{
		"duplicate":          synthetic + "kind: Config\n",
		"multidocument":      synthetic + "---\n" + synthetic,
		"unknown-auth":       strings.Replace(synthetic, "token: SYNTHETIC-NOT-A-REAL-TOKEN", "tokenFile: /not/read", 1),
		"exec":               strings.Replace(synthetic, "token: SYNTHETIC-NOT-A-REAL-TOKEN", "exec: {command: /not/executed}", 1),
		"http":               strings.Replace(synthetic, "https://", "http://", 1),
		"credentials-in-url": strings.Replace(synthetic, "https://example.invalid", "https://name:secret@example.invalid", 1),
		"insecure":           strings.Replace(synthetic, "server: https://example.invalid", "server: https://example.invalid\n    insecure-skip-tls-verify: true", 1),
		"preferences":        synthetic + "preferences: {secret: hidden}\n",
		"unknown-context":    strings.Replace(synthetic, "current-context: demo", "current-context: missing", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := prepare([]byte(data), t.TempDir(), "/test", "/helper", nil); e == nil {
				t.Fatal("unsafe source accepted")
			}
		})
	}
	p, _ := samplePayload(t)
	b, _ := json.Marshal(p.Projection)
	if bytes.Contains(b, []byte("SYNTHETIC-NOT-A-REAL-TOKEN")) {
		t.Fatal("token leaked to generated projection")
	}
	if p.Source != synthetic || p.Projection.Users[0].User.Exec.Interactive != "Never" {
		t.Fatal("source or exec contract changed")
	}
}

func TestProjectionAndSelection(t *testing.T) {
	p, _ := samplePayload(t)
	next, _ := samplePayload(t)
	observed := p.Projection
	observed.Contexts = append([]namedContext(nil), observed.Contexts...)
	observed.Contexts[0].Context.Namespace = "chosen"
	if !equalProjection(p.Projection, observed) {
		t.Fatal("namespace should be client-selectable")
	}
	preserveSelections(p, next, observed)
	if next.Projection.Contexts[0].Context.Namespace != "chosen" || next.Portable.Contexts[0].Context.Namespace != "" {
		t.Fatal("selection handling mutated source")
	}
	altered := p.Projection
	altered.Clusters = append([]namedCluster(nil), altered.Clusters...)
	altered.Clusters[0].Cluster.Server = "https://other.invalid"
	if equalProjection(p.Projection, altered) {
		t.Fatal("destination change accepted")
	}
	if binding(p.Projection.Clusters[0].Cluster) == binding(altered.Clusters[0].Cluster) {
		t.Fatal("destination binding collision")
	}
	changed, e := prepare([]byte(strings.Replace(synthetic, "SYNTHETIC-NOT-A-REAL-TOKEN", "SYNTHETIC-REPLACEMENT", 1)), "/base", "/synthetic/state", "/synthetic/helper", p)
	if e != nil || changed.Records["demo"].ID != p.Records["demo"].ID {
		t.Fatal("edit did not preserve credential ID")
	}
}

func TestPrivateFileHandling(t *testing.T) {
	d := privateTemp(t)
	path := filepath.Join(d, "private")
	if e := writeNew(path, []byte("synthetic")); e != nil {
		t.Fatal(e)
	}
	if e := writeNew(path, []byte("replacement")); e == nil {
		t.Fatal("overwrote existing output")
	}
	link := filepath.Join(d, "link")
	if e := os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	if _, e := readBounded(link, 100, true); e == nil {
		t.Fatal("followed secret symlink")
	}
	if e := os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := readBounded(path, 100, true); e == nil {
		t.Fatal("accepted public private-file permissions")
	}
	if _, e := readBounded(path, 1, false); e == nil {
		t.Fatal("accepted oversized input")
	}
}

func TestAgeAuthenticationRecoveryAndCommit(t *testing.T) {
	p, recovery := samplePayload(t)
	daily, e := age.GenerateHybridIdentity()
	if e != nil {
		t.Fatal(e)
	}
	cipher, e := encryptPayload(p, daily.Recipient())
	if e != nil {
		t.Fatal(e)
	}
	for _, identity := range []age.Identity{daily, recovery} {
		decoded, e := decryptPayload(cipher, identity)
		if e != nil || !samePayload(p, decoded) {
			t.Fatal("recipient roundtrip failed")
		}
	}
	bad := bytes.Clone(cipher)
	bad[len(bad)-1] ^= 1
	if _, e := decryptPayload(bad, recovery); e == nil {
		t.Fatal("accepted tampered payload")
	}
	wrong, _ := age.GenerateHybridIdentity()
	if _, e := decryptPayload(cipher, wrong); e == nil {
		t.Fatal("accepted unrelated recovery key")
	}
	d := privateTemp(t)
	id, e := commitSnapshot(d, "", p, cipher)
	if e != nil {
		t.Fatal(e)
	}
	snap, e := loadSnapshot(d)
	if e != nil || snap.ID != id || !bytes.Equal(snap.Cipher, cipher) {
		t.Fatal("generation roundtrip failed")
	}
	if _, e = commitSnapshot(d, "wrong", p, cipher); e == nil {
		t.Fatal("accepted stale commit")
	}
	current, _ := currentID(d)
	if current != id {
		t.Fatal("stale commit replaced vault")
	}
	keyPath := filepath.Join(d, "offline-key")
	if e = writeNew(keyPath, []byte(recovery.String())); e != nil {
		t.Fatal(e)
	}
	// Recovery needs only ciphertext and the private recovery key; metadata may be lost.
	if e = os.Remove(filepath.Join(d, "generations", id, "metadata.json")); e != nil {
		t.Fatal(e)
	}
	out := filepath.Join(d, "recovered")
	if e = recoverFile(filepath.Join(d, "generations", id, "vault.age"), keyPath, out); e != nil {
		t.Fatal(e)
	}
	recovered, e := readBounded(out, maxSource, true)
	if e != nil {
		t.Fatal(e)
	}
	c, e := parseConfig(recovered)
	if e != nil || c.Users[0].User.Token != "SYNTHETIC-NOT-A-REAL-TOKEN" {
		t.Fatal("portable recovery failed")
	}
}

func TestSessionExpiryBindingsAndLock(t *testing.T) {
	p, key := samplePayload(t)
	d := privateTemp(t)
	cipher, e := encryptPayload(p, key.Recipient())
	if e != nil {
		t.Fatal(e)
	}
	id, e := commitSnapshot(d, "", p, cipher)
	if e != nil {
		t.Fatal(e)
	}
	s := &service{state: d, ttl: time.Hour, stop: make(chan struct{})}
	if e = s.cachePayload(0, p, id); e != nil {
		t.Fatal(e)
	}
	req := request{Op: "credential", ID: p.Records["demo"].ID, Cluster: &p.Projection.Clusters[0].Cluster}
	if _, e = s.credential(context.Background(), 0, req); e != nil {
		t.Fatal(e)
	}
	other := *req.Cluster
	other.Server = "https://different.invalid"
	req.Cluster = &other
	if _, e = s.credential(context.Background(), 0, req); e == nil {
		t.Fatal("released token to different destination")
	}
	s.cache.WallDeadline = time.Now().Add(-time.Second)
	if s.status()["unlocked"] != false {
		t.Fatal("wall expiry not enforced")
	}
	if e = s.cachePayload(0, p, id); e != nil {
		t.Fatal(e)
	}
	s.cache.Deadline = time.Now().Add(-time.Second)
	if s.status()["unlocked"] != false {
		t.Fatal("monotonic expiry not enforced")
	}
	if e = privateDir(filepath.Dir(s.editPath())); e != nil {
		t.Fatal(e)
	}
	if e = writeNew(s.editPath(), []byte(synthetic)); e != nil {
		t.Fatal(e)
	}
	result := s.lock(false)
	if result["fully_locked"] != false || result["edit_open"] != true {
		t.Fatal("lock hid the remaining plaintext edit")
	}
	if e = s.cachePayload(0, p, id); e == nil {
		t.Fatal("late unlock survived lock epoch")
	}
}

func TestBrowserHTTPBoundaryAndReplay(t *testing.T) {
	c := &ceremony{cap: strings.Repeat("a", 64), origin: "http://localhost:12345", reply: make(chan browserMessage, 1), page: browserPage{Request: &browserMessage{ID: "one-use", Op: "unwrap"}}}
	call := func(host, origin, cap, body string) int {
		r := httptest.NewRequest("POST", "http://localhost:12345/api/reply", strings.NewReader(body))
		r.Host = host
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Unlock-Capability", cap)
		w := httptest.NewRecorder()
		c.serve(w, r)
		return w.Code
	}
	for _, bad := range []struct{ host, origin, cap string }{{"attacker.invalid", c.origin, c.cap}, {"localhost:12345", "https://attacker.invalid", c.cap}, {"localhost:12345", c.origin, "wrong"}} {
		if call(bad.host, bad.origin, bad.cap, `{"id":"one-use"}`) != 403 {
			t.Fatal("cross-origin or unprivileged reply accepted")
		}
	}
	if call("localhost:12345", c.origin, c.cap, `{"id":"stale"}`) != 409 {
		t.Fatal("stale reply accepted")
	}
	if call("localhost:12345", c.origin, c.cap, `{"id":"one-use","failed":true}`) != 200 {
		t.Fatal("valid reply rejected")
	}
	if call("localhost:12345", c.origin, c.cap, `{"id":"one-use"}`) != 409 {
		t.Fatal("replayed reply accepted")
	}
}

func TestTokenExpiryOnlyShortensSession(t *testing.T) {
	deadline := time.Now().Add(time.Hour)
	if !tokenDeadline("opaque", deadline).Equal(deadline) {
		t.Fatal("opaque token changed deadline")
	}
	if !tokenDeadline("x.eyJleHAiOjF9.x", deadline).Before(time.Now()) {
		t.Fatal("expired JWT extended session")
	}
}

func TestPrivateFileNavigationDoesNotRelaxAPI(t *testing.T) {
	c := &ceremony{cap: strings.Repeat("a", 64), origin: "http://localhost:12345", reply: make(chan browserMessage, 1)}
	for _, tc := range []struct {
		method, path, dest string
		status             int
	}{
		{"GET", "/", "document", 200},
		{"GET", "/", "iframe", 403},
		{"GET", "/app.js", "document", 403},
		{"POST", "/api/poll", "document", 403},
		{"POST", "/api/reply", "document", 403},
	} {
		t.Run(tc.method+tc.path+tc.dest, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, c.origin+tc.path, strings.NewReader("{}"))
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			r.Header.Set("Sec-Fetch-Mode", "navigate")
			r.Header.Set("Sec-Fetch-Dest", tc.dest)
			if tc.method == "POST" {
				r.Header.Set("Origin", c.origin)
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("X-Unlock-Capability", c.cap)
			}
			w := httptest.NewRecorder()
			c.serve(w, r)
			if w.Code != tc.status {
				t.Fatalf("unexpected HTTP status: %d", w.Code)
			}
			if strings.Contains(w.Body.String(), c.cap) {
				t.Fatal("landing page leaked capability")
			}
		})
	}
}
