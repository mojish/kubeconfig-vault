package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

func TestClientProjectionRoundTrip(t *testing.T) {
	p, _ := samplePayload(t)
	want := p.Projection
	secondCluster, secondUser, secondContext := want.Clusters[0], want.Users[0], want.Contexts[0]
	secondCluster.Name, secondUser.Name, secondContext.Name = "alternate", "other", "second"
	secondContext.Context.Cluster, secondContext.Context.User = secondCluster.Name, secondUser.Name
	want.Clusters = append(want.Clusters, secondCluster)
	want.Users = append(want.Users, secondUser)
	want.Contexts = append(want.Contexts, secondContext)
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	for _, reverse := range []bool{false, true} {
		for _, env := range []string{"null", "[]"} {
			field := `"env":` + env
			data := strings.ReplaceAll(string(raw), `"command":`, field+`,"command":`)
			got, err := parseConfig([]byte(data))
			if err != nil {
				t.Fatal(err)
			}
			if reverse {
				slices.Reverse(got.Clusters)
				slices.Reverse(got.Users)
				slices.Reverse(got.Contexts)
			}
			got.Current, got.Contexts[0].Context.Namespace = "second", "changed"
			if !equalProjection(got, want) {
				t.Fatal("client selection or ordering rejected")
			}
			if _, err := parseConfig([]byte(strings.Replace(data, field, `"env":[{"name":"OVERRIDE","value":"synthetic"}]`, 1))); err == nil {
				t.Fatal("nonempty exec environment accepted")
			}
			if _, err := parseConfig([]byte(strings.Replace(data, field, `"unknown":true`, 1))); err == nil {
				t.Fatal("unmanaged exec field accepted")
			}
			got.Users[0].User.Exec.Args[0], got.Users[0].User.Exec.Args[1] = got.Users[0].User.Exec.Args[1], got.Users[0].User.Exec.Args[0]
			if equalProjection(got, want) {
				t.Fatal("reordered exec arguments accepted")
			}
		}
	}
	for _, replace := range []func(*config){
		func(c *config) { c.Clusters[0].Name = c.Clusters[1].Name },
		func(c *config) { c.Users[0].Name = c.Users[1].Name },
		func(c *config) { c.Contexts[0].Name = c.Contexts[1].Name },
		func(c *config) { c.Users[0].User.Exec.Command += "-other" },
		func(c *config) { c.Contexts[0].Context.User = secondUser.Name },
		func(c *config) { c.Clusters[0].Cluster.TLSName = "other.invalid" },
	} {
		got, err := parseConfig(raw)
		if err != nil {
			t.Fatal(err)
		}
		replace(&got)
		if equalProjection(got, want) {
			t.Fatal("substituted managed field accepted")
		}
	}
}

func TestKubectlWritesInEitherOrder(t *testing.T) {
	kubectl, err := exec.LookPath("kubectl")
	if err != nil {
		t.Skip("kubectl is required for real client writes")
	}
	for _, order := range [][]string{{"alpha", "zulu"}, {"zulu", "alpha"}} {
		for _, action := range []string{"context", "namespace"} {
			t.Run(order[0]+"-first/"+action, func(t *testing.T) {
				p, _ := samplePayload(t)
				c := p.Projection
				for _, name := range order {
					entry := c.Contexts[0]
					entry.Name = name
					c.Contexts = append(c.Contexts, entry)
				}
				c.Contexts = c.Contexts[1:]
				c.Current = order[0]
				dir := privateTemp(t)
				path := filepath.Join(dir, "config")
				t.Setenv("HOME", dir)
				t.Setenv("KUBECONFIG", path)
				raw, err := serializeConfig(c)
				if err != nil {
					t.Fatal(err)
				}
				if err := writeNew(path, raw); err != nil {
					t.Fatal(err)
				}
				args := []string{"--kubeconfig", path, "config"}
				if action == "context" {
					args = append(args, "use-context", order[1])
				} else {
					args = append(args, "set-context", "--current", "--namespace", "vault-test")
				}
				if err := exec.Command(kubectl, args...).Run(); err != nil {
					t.Fatal(err)
				}
				updated, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				got, err := parseConfig(updated)
				if err != nil || !equalProjection(c, got) {
					t.Fatal("kubectl write changed managed settings", err)
				}
			})
		}
	}
}

func TestBackupIndependentOfGeneratedConfig(t *testing.T) {
	p, key := samplePayload(t)
	state := privateTemp(t)
	cipher, err := encryptPayload(p, key.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	id, err := commitSnapshot(state, "", p, cipher)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(state, "generations", id)
	file := filepath.Join(dir, "kubeconfig")
	if err := os.WriteFile(file, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, missing := range []bool{false, true} {
		if missing {
			if err := os.Remove(file); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(dir, "metadata.json")); err != nil {
				t.Fatal(err)
			}
		}
		out := filepath.Join(t.TempDir(), "copy.age")
		if err := backupGeneration(state, out); err != nil {
			t.Fatal(err)
		}
		if _, err := readRecovered(out, key); err != nil {
			t.Fatal(err)
		}
		if err := backupGeneration(state, out); err == nil {
			t.Fatal("existing destination overwritten")
		}
	}
	second, err := encryptPayload(p, key.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 6 {
		out := filepath.Join(t.TempDir(), "snapshot")
		wg.Go(func() {
			if err := backupGeneration(state, out); err != nil {
				t.Error(err)
				return
			}
			b, err := os.ReadFile(out)
			if err != nil || !(bytes.Equal(b, cipher) || bytes.Equal(b, second)) {
				t.Error("incomplete concurrent backup")
			}
		})
	}
	_, err = commitSnapshot(state, id, p, second)
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
}

func TestCompareEncryptedBackupsAcrossSaves(t *testing.T) {
	state, dir := privateTemp(t), privateTemp(t)
	p, key := samplePayload(t)
	var previous string
	for _, name := range []string{"first", "second"} {
		p.Portable.Contexts[0].Context.Namespace = name
		cipher, err := encryptPayload(p, key.Recipient())
		if err != nil {
			t.Fatal(err)
		}
		previous, err = commitSnapshot(state, previous, p, cipher)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name+".age")
		if err := run([]string{"--state-dir", state, "backup", path}); err != nil {
			t.Fatal(err)
		}
		if err := run([]string{"--state-dir", state, "backup", "--compare", path}); err != nil {
			t.Fatal(err)
		}
	}
	old := filepath.Join(dir, "first.age")
	if err := run([]string{"--state-dir", state, "backup", "--compare", old}); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("expected a different encrypted save, got %v", err)
	}
	for _, name := range []string{"first", "second"} {
		got, err := readRecovered(filepath.Join(dir, name+".age"), key)
		if err != nil || got.Portable.Contexts[0].Context.Namespace != name {
			t.Fatal("both backups must still recover the corresponding edit", err)
		}
	}
	if err := os.Symlink(old, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := writeNew(filepath.Join(dir, "invalid"), []byte("not an age file")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"missing", "invalid", "link"} {
		if err := compareBackup(state, filepath.Join(dir, name)); err == nil || strings.Contains(err.Error(), "differs") {
			t.Errorf("expected a read or format error for %s, got %v", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(state, "daemon.lock")); !os.IsNotExist(err) {
		t.Fatal("offline comparison started a helper", err)
	}
}

func TestProxyPrivacyAndLegacyRecovery(t *testing.T) {
	p, key := samplePayload(t)
	const marker = "SYNTHETIC-PRIVATE-PARAMETER"
	for _, suffix := range []string{"?query=" + marker, "#" + marker, "?", "#"} {
		src := strings.Replace(synthetic, "server:", "proxy-url: 'https://proxy.invalid"+suffix+"'\n    server:", 1)
		_, err := prepare([]byte(src), "", "", "", nil)
		if err == nil || strings.Contains(err.Error(), marker) || !strings.Contains(err.Error(), "proxy-url") {
			t.Fatal("missing safe proxy-url diagnostic")
		}
	}
	for _, scheme := range []string{"http", "https", "socks5"} {
		src := strings.Replace(synthetic, "server:", "proxy-url: '"+scheme+"://proxy.invalid:3128'\n    server:", 1)
		if _, err := prepare([]byte(src), "", "", "", nil); err != nil {
			t.Fatal(err)
		}
	}
	// Construct a legacy encrypted backup without running the old installer.
	p.Portable.Clusters[0].Cluster.Proxy = "https://proxy.invalid/?q=" + marker
	cipher, err := encryptPayload(p, key.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(privateTemp(t), "old.age")
	if err := writeNew(path, cipher); err != nil {
		t.Fatal(err)
	}
	got, err := readRecovered(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if got.Portable.Clusters[0].Cluster.Proxy != p.Portable.Clusters[0].Cluster.Proxy {
		t.Fatal("private recovery lost the original proxy URL")
	}
	s := service{state: privateTemp(t), browser: filepath.Join(t.TempDir(), "unused-browser")}
	_, err = s.restoreBackup(context.Background(), request{Path: path, RecoveryIdentity: []byte(key.String())})
	if err == nil || !strings.Contains(err.Error(), "proxy-url") || strings.Contains(err.Error(), marker) {
		t.Fatal("legacy restore should request a corrected proxy before enrollment")
	}
}

func TestSetupAuthenticationErrorsAreRedacted(t *testing.T) {
	const marker = "PRIVATE-TEST-VALUE"
	for _, field := range []string{"tokenFile", "auth-provider", "password", "username", "client-key-data", "client-certificate"} {
		src := strings.Replace(synthetic, "token: SYNTHETIC-NOT-A-REAL-TOKEN", field+": "+marker, 1)
		raw := filepath.Join(privateTemp(t), "input")
		if err := writeNew(raw, []byte(src)); err != nil {
			t.Fatal(err)
		}
		err := run([]string{"--state-dir", privateTemp(t), "setup", raw})
		if err == nil || !strings.Contains(err.Error(), "user."+field) || strings.Contains(err.Error(), marker) {
			t.Fatal("missing redacted setup diagnostic", field, err)
		}
	}
}
