package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"gopkg.in/yaml.v3"
)

// Security regressions derived from the review, using synthetic data only.
func auditCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	secret, e := x509.MarshalECPrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: secret})
}

func TestPublicCABoundary(t *testing.T) {
	cert, private := auditCertificate(t)
	malformed := append([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n"), cert...)
	for name, data := range map[string][]byte{
		"private-key":            append(bytes.Clone(cert), private...),
		"leading-secret":         append([]byte("synthetic-secret\n"), cert...),
		"trailing-secret":        append(bytes.Clone(cert), []byte("synthetic-secret")...),
		"malformed-before-valid": malformed,
		"pem-headers":            bytes.Replace(cert, []byte("-----BEGIN CERTIFICATE-----\n"), []byte("-----BEGIN CERTIFICATE-----\nSecret: synthetic\n\n"), 1),
		"invalid-der":            pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")}),
		"empty":                  []byte(" \n"),
	} {
		for _, file := range []bool{false, true} {
			t.Run(name+strconv.FormatBool(file), func(t *testing.T) {
				d := privateTemp(t)
				c, e := parseConfig([]byte(synthetic))
				if e != nil {
					t.Fatal(e)
				}
				if file {
					path := filepath.Join(d, "ca.pem")
					if e = writeNew(path, data); e != nil {
						t.Fatal(e)
					}
					c.Clusters[0].Cluster.CAFile = path
				} else {
					c.Clusters[0].Cluster.CA = base64.StdEncoding.EncodeToString(data)
				}
				source, e := yaml.Marshal(c)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = prepare(source, d, d, "/synthetic/helper", nil); e == nil {
					t.Fatal("non-public CA material accepted")
				}
			})
		}
	}
	public, e := publicCertificates(append(append([]byte(" \n"), cert...), cert...))
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(public, bytes.Repeat(cert, 2)) {
		t.Fatal("valid certificate bundle changed unexpectedly")
	}
}

func TestExpandedCARejectedBeforeCommit(t *testing.T) {
	cert, _ := auditCertificate(t)
	bundle := bytes.Repeat(cert, (3*1024*1024+262144)/len(cert))
	d := privateTemp(t)
	ca := filepath.Join(d, "bundle.pem")
	if e := writeNew(ca, bundle); e != nil {
		t.Fatal(e)
	}
	c, e := parseConfig([]byte(synthetic))
	if e != nil {
		t.Fatal(e)
	}
	c.Clusters[0].Cluster.CAFile = ca
	source, e := yaml.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = prepare(source, d, d, "/synthetic/helper", nil); e == nil {
		t.Fatal("oversized expanded projection accepted")
	}
	if id, e := currentID(d); e != nil || id != "" {
		t.Fatal("rejected preparation published a generation")
	}
}

func TestSelectedCAFileAndSharedBudget(t *testing.T) {
	dir := privateTemp(t)
	path := filepath.Join(dir, "ca.pem")
	if err := writeNew(path, nil); err != nil {
		t.Fatal(err)
	}
	fromFile := cluster{CAFile: "ca.pem"}
	if _, err := embedClusterCA(&fromFile, dir, maxSource); err == nil {
		t.Fatal("empty selected CA file accepted as system trust")
	}
	cert, _ := auditCertificate(t)
	if err := os.WriteFile(path, cert, 0600); err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(cert)
	used, err := embedClusterCA(&fromFile, dir, len(encoded))
	if err != nil || used != len(encoded) || fromFile.CA != encoded || fromFile.CAFile != "" {
		t.Fatal("valid file did not fit its exact budget")
	}
	inline := cluster{CA: encoded}
	if _, err := embedClusterCA(&inline, dir, used-1); err == nil {
		t.Fatal("second cluster exceeded the remaining budget")
	}
}

func TestCommitReaderLimitsPreserveCurrent(t *testing.T) {
	for _, kind := range []string{"projection", "portable", "metadata", "invalid-metadata"} {
		t.Run(kind, func(t *testing.T) {
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
			switch kind {
			case "projection":
				p.Projection.Current = strings.Repeat("x", maxSource)
			case "portable":
				p.Portable.Current = strings.Repeat("x", maxSource)
			case "metadata":
				p.Meta.Identity = strings.Repeat("x", 65537)
			case "invalid-metadata":
				p.Meta.Version = 2
			}
			if _, e = commitSnapshot(d, id, p, cipher); e == nil {
				t.Fatal("unreadable candidate committed")
			}
			snap, e := loadSnapshot(d)
			if e != nil || snap.ID != id {
				t.Fatal("failed candidate replaced current")
			}
		})
	}
}

func testBootstrapURL(t *testing.T, launch []byte) *url.URL {
	t.Helper()
	u, e := url.Parse(string(launch))
	if e != nil || u.Scheme != "file" || u.Fragment != "" {
		t.Fatal("launcher did not receive a private file URI")
	}
	data, e := readBounded(u.Path, 8192, true)
	if e != nil {
		t.Fatal("cannot read synthetic bootstrap")
	}
	_, tail, ok := strings.Cut(string(data), "0;url=")
	if !ok {
		t.Fatal("bootstrap redirect missing")
	}
	value, _, ok := strings.Cut(tail, "\"")
	if !ok {
		t.Fatal("bootstrap redirect invalid")
	}
	target, e := url.Parse(value)
	if e != nil || target.Scheme != "http" || target.Hostname() != "localhost" || len(target.Fragment) != 64 {
		t.Fatal("invalid synthetic target")
	}
	return target
}

type auditRecipient struct{ key []byte }

func (a *auditRecipient) Wrap(key []byte) ([]*age.Stanza, error) {
	a.key = bytes.Clone(key)
	return []*age.Stanza{{Type: recipientType, Args: []string{base64.RawStdEncoding.EncodeToString(make([]byte, 16))}, Body: make([]byte, 32)}}, nil
}
func (a *auditRecipient) WrapWithLabels(key []byte) ([]*age.Stanza, []string, error) {
	s, e := a.Wrap(key)
	return s, []string{"postquantum"}, e
}

func TestSavePreservesChangesDuringAuthentication(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(strconv.FormatBool(replace), func(t *testing.T) { testSaveChangedEdit(t, replace) })
	}
}

func testSaveChangedEdit(t *testing.T, replace bool) {
	p, _ := samplePayload(t)
	d := privateTemp(t)
	recipient := &auditRecipient{}
	cipher, e := encryptPayload(p, recipient)
	if e != nil {
		t.Fatal(e)
	}
	id, e := commitSnapshot(d, "", p, cipher)
	if e != nil {
		t.Fatal(e)
	}
	launcher := filepath.Join(d, "browser")
	if e = os.WriteFile(launcher, []byte("#!/bin/sh\numask 077\nprintf '%s' \"$1\" > \"$0.url\"\n"), 0700); e != nil {
		t.Fatal(e)
	}
	s := &service{state: d, executable: "/synthetic/helper", browser: launcher, ttl: time.Hour, stop: make(chan struct{})}
	// Projection paths must match those used by saveEdit; this does not touch real data.
	for i := range p.Projection.Users {
		p.Projection.Users[i].User.Exec.Args[1] = d
	}
	cipher, e = encryptPayload(p, recipient)
	if e != nil {
		t.Fatal(e)
	}
	id, e = commitSnapshot(d, id, p, cipher)
	if e != nil {
		t.Fatal(e)
	}
	if e = privateDir(filepath.Dir(s.editPath())); e != nil {
		t.Fatal(e)
	}
	before := strings.Replace(synthetic, "SYNTHETIC-NOT-A-REAL-TOKEN", "SYNTHETIC-OLDER-EDIT", 1)
	later := strings.Replace(synthetic, "SYNTHETIC-NOT-A-REAL-TOKEN", "SYNTHETIC-NEWER-EDIT", 1)
	if e = writeNew(s.editPath(), []byte(before)); e != nil {
		t.Fatal(e)
	}
	if e = writeNew(filepath.Join(d, "edit", "generation"), []byte(id)); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := s.saveEdit(ctx, false); result <- err }()
	var launch []byte
	for i := 0; i < 200; i++ {
		launch, e = os.ReadFile(launcher + ".url")
		if e == nil && len(launch) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if e != nil {
		t.Fatal("synthetic browser did not start")
	}
	u := testBootstrapURL(t, launch)
	capability := u.Fragment
	u.Fragment = ""
	origin := strings.TrimSuffix(u.String(), "/")
	client := &http.Client{Timeout: 3 * time.Second}
	call := func(path string, v any, out any) {
		t.Helper()
		b, _ := json.Marshal(v)
		req, e := http.NewRequestWithContext(ctx, "POST", origin+path, bytes.NewReader(b))
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Origin", origin)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Unlock-Capability", capability)
		r, e := client.Do(req)
		if e != nil {
			t.Fatal("synthetic callback failed")
		}
		defer r.Body.Close()
		if r.StatusCode != 200 {
			t.Fatal("synthetic callback rejected")
		}
		if out != nil {
			if e = json.NewDecoder(r.Body).Decode(out); e != nil {
				t.Fatal(e)
			}
		} else {
			io.Copy(io.Discard, r.Body)
		}
	}
	var nextKey []byte
	for step := 1; step <= 3; step++ {
		var page browserPage
		for i := 0; i < 200; i++ {
			call("/api/poll", map[string]any{}, &page)
			if page.Request != nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if page.Request == nil {
			t.Fatal("no pending synthetic browser step")
		}
		req := page.Request
		reply := browserMessage{ID: req.ID}
		switch step {
		case 1:
			if req.Op != "unwrap" {
				t.Fatal("unexpected first operation")
			}
			target := s.editPath()
			if replace {
				target = filepath.Join(d, "new-edit")
			}
			if e = os.WriteFile(target, []byte(later), 0600); e != nil {
				t.Fatal(e)
			}
			if replace {
				if e = os.Rename(target, s.editPath()); e != nil {
					t.Fatal(e)
				}
			}
			reply.FileKey = recipient.key
		case 2:
			if req.Op != "wrap" {
				t.Fatal("unexpected second operation")
			}
			nextKey = bytes.Clone(req.FileKey)
			reply.Stanzas = []stanza{{Type: recipientType, Args: []string{base64.RawStdEncoding.EncodeToString(make([]byte, 16))}, Body: make([]byte, 32)}}
		case 3:
			reply.FileKey = nextKey
		}
		call("/api/reply", reply, nil)
	}
	if e = <-result; e == nil {
		t.Fatal("concurrent editor change was not reported")
	}
	retained, e := readBounded(s.editPath(), maxSource, true)
	if e != nil || string(retained) != later {
		t.Fatal("newer edit not preserved")
	}
	snap, e := loadSnapshot(d)
	if e != nil || snap.ID != id {
		t.Fatal("concurrent edit published an obsolete snapshot")
	}
	if s.status()["fully_locked"] != false {
		t.Fatal("remaining plaintext hidden")
	}
}

func TestFinalizePreservesLateWritesAndFailures(t *testing.T) {
	for _, kind := range []string{"replacement", "open-handle", "commit-failure"} {
		t.Run(kind, func(t *testing.T) {
			d := privateTemp(t)
			s := &service{state: d}
			if e := privateDir(filepath.Dir(s.editPath())); e != nil {
				t.Fatal(e)
			}
			old := []byte("synthetic-old")
			newer := []byte("synthetic-new")
			if e := writeNew(s.editPath(), old); e != nil {
				t.Fatal(e)
			}
			f, e := os.OpenFile(s.editPath(), os.O_WRONLY, 0)
			if e != nil {
				t.Fatal(e)
			}
			defer f.Close()
			e = s.finalizeEdit(old, "vault saved", func() error {
				switch kind {
				case "replacement":
					return writeNew(s.editPath(), newer)
				case "open-handle":
					_, err := f.WriteAt(newer, 0)
					return err
				default:
					return context.Canceled
				}
			})
			if e == nil {
				t.Fatal("finalization conflict not reported")
			}
			wanted := newer
			if kind == "commit-failure" {
				wanted = old
			}
			got, e := readBounded(s.editPath(), maxSource, true)
			if e != nil || !bytes.Equal(got, wanted) {
				t.Fatal("edit was lost during finalization")
			}
		})
	}
}

func TestInterruptedEditRemainsVisibleAndDiscardable(t *testing.T) {
	d := privateTemp(t)
	s := &service{state: d}
	if err := privateDir(filepath.Dir(s.editPath())); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{s.editPath(), s.pendingEditPath()} {
		if err := writeNew(path, []byte("synthetic retained edit")); err != nil {
			t.Fatal(err)
		}
	}
	status := s.lock(false)
	if status["fully_locked"] != false || len(status["edit_paths"].([]string)) != 2 {
		t.Fatal("interrupted plaintext hidden")
	}
	for _, op := range []string{"config-unlock", "config-lock"} {
		if _, err := s.handle(context.Background(), request{Op: op}); err == nil {
			t.Fatal("interrupted edit overwritten")
		}
	}
	result, err := s.handle(context.Background(), request{Op: "config-discard"})
	if err != nil || result.(map[string]any)["fully_locked"] != true {
		t.Fatal("explicit discard left plaintext behind")
	}
}

func TestBootstrapRemovedOnLaunchFailureAndCancellation(t *testing.T) {
	t.Setenv("TMPDIR", privateTemp(t))
	if _, err := newCeremony(context.Background(), "synthetic", "/nonexistent-synthetic-browser", 1); err == nil {
		t.Fatal("invalid launcher accepted")
	}
	entries, err := os.ReadDir(os.Getenv("TMPDIR"))
	if err != nil || len(entries) != 0 {
		t.Fatal("failed launch left bootstrap behind")
	}
	c, err := newCeremony(context.Background(), "synthetic", "/usr/bin/true", 1)
	if err != nil {
		t.Fatal(err)
	}
	c.cancel()
	for i := 0; i < 100; i++ {
		if _, err = os.Stat(c.bootstrap); os.IsNotExist(err) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("cancelled ceremony left bootstrap behind")
}

func TestBackgroundTabCanReadCompletionAndCloseListener(t *testing.T) {
	c, err := newCeremony(context.Background(), "synthetic completion", "/usr/bin/true", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer c.cancel()
	c.finish(true)
	// A scheduled/background tab can miss the old 1.5-second delivery window.
	select {
	case <-c.ctx.Done():
		t.Fatal("listener closed before a background tab could read completion")
	case <-time.After(2 * time.Second):
	}
	req, err := http.NewRequest(http.MethodPost, c.origin+"/api/poll", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", c.origin)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Unlock-Capability", c.cap)
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		t.Fatal("background tab could not read final status")
	}
	defer resp.Body.Close()
	var page browserPage
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&page) != nil ||
		!page.Done || !page.Success || page.Request != nil {
		t.Fatal("expected only the successful final state")
	}
	select {
	case <-c.ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("listener remained open after delivery")
	}
}

func TestLaunchArgumentsDoNotAuthorizeFileKeyAccess(t *testing.T) {
	if _, e := os.Stat("/proc/self/cmdline"); e != nil {
		t.Skip("Linux procfs probe")
	}
	d := privateTemp(t)
	launcher := filepath.Join(d, "browser")
	script := "#!/usr/bin/python3\nimport os, pathlib, time\npathlib.Path(__file__ + '.pid').write_text(str(os.getpid()))\ntime.sleep(15)\n"
	if e := os.WriteFile(launcher, []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	c, e := newCeremony(context.Background(), "synthetic audit", launcher, 1)
	if e != nil {
		t.Fatal(e)
	}
	defer c.cancel()
	var raw []byte
	for i := 0; i < 200; i++ {
		raw, e = os.ReadFile(launcher + ".pid")
		if e == nil && len(raw) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e != nil {
		t.Fatal("synthetic launcher did not start")
	}
	pid, e := strconv.Atoi(string(raw))
	if e != nil {
		t.Fatal(e)
	}
	proc, e := os.FindProcess(pid)
	if e != nil {
		t.Fatal(e)
	}
	defer proc.Kill()
	args, e := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(args, []byte(c.cap)) || bytes.Contains(args, []byte(c.origin)) {
		t.Fatal("browser arguments exposed bridge capability or endpoint")
	}
	var launch []byte
	for _, arg := range bytes.Split(args, []byte{0}) {
		if bytes.HasPrefix(arg, []byte("file://")) {
			launch = arg
			break
		}
	}
	if launch == nil {
		t.Fatal("missing private bootstrap URI")
	}
	fileURL, e := url.Parse(string(launch))
	if e != nil {
		t.Fatal("invalid bootstrap URI")
	}
	for _, path := range []string{fileURL.Path, filepath.Dir(fileURL.Path)} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm()&0077 != 0 {
			t.Fatal("bootstrap permissions are not private")
		}
	}
	captured := testBootstrapURL(t, launch)
	capability := captured.Fragment
	captured.Fragment = ""
	origin := strings.TrimSuffix(captured.String(), "/")
	// The observable launch URI is not itself an HTTP capability.
	req, _ := http.NewRequest("POST", origin+"/api/poll", strings.NewReader("{}"))
	req.Header.Set("Origin", origin)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Unlock-Capability", string(launch))
	denied, err := (&http.Client{Timeout: time.Second}).Do(req)
	if err != nil {
		t.Fatal("synthetic denial request failed")
	}
	denied.Body.Close()
	if denied.StatusCode != 403 {
		t.Fatal("launch URI authorized polling")
	}
	key := bytes.Repeat([]byte{42}, 16)
	defer clear(key)
	done := make(chan struct{})
	go func() { defer close(done); _, _ = c.exchange(browserMessage{Op: "wrap", FileKey: key}) }()
	defer func() { c.cancel(); <-done }()
	client := &http.Client{Timeout: time.Second}
	var page browserPage
	for i := 0; i < 100; i++ {
		req, err := http.NewRequest("POST", origin+"/api/poll", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Origin", origin)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Unlock-Capability", capability)
		res, err := client.Do(req)
		if err != nil {
			t.Fatal("synthetic API request failed")
		}
		err = json.NewDecoder(res.Body).Decode(&page)
		res.Body.Close()
		if err != nil {
			t.Fatal("synthetic response invalid")
		}
		if page.Request != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if page.Request == nil || !bytes.Equal(page.Request.FileKey, key) {
		t.Fatal("capability did not expose synthetic pending file key")
	}
	clear(page.Request.FileKey)
	if _, err := os.Stat(fileURL.Path); !os.IsNotExist(err) {
		t.Fatal("bootstrap not removed after authenticated handoff")
	}
}
