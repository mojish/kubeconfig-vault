package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func syntheticClientPair(t *testing.T, configure func(*x509.Certificate)) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	if configure != nil {
		configure(leaf)
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: secret})
}

func TestClientCertificatePurpose(t *testing.T) {
	encode := base64.StdEncoding.EncodeToString
	ca, signer := auditCertificate(t)
	if _, err := parseClientCertificate(encode(ca), encode(signer)); err == nil {
		t.Fatal("accepted CA signing credential")
	}
	for _, tc := range []struct {
		profile func(*x509.Certificate)
		ok      bool
	}{
		{func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }, true},
		{func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} }, true},
		{func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }, false},
		{func(c *x509.Certificate) {
			c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 55555, 1}}
		}, false},
		{func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment }, false},
	} {
		leaf, key := syntheticClientPair(t, tc.profile)
		_, err := parseClientCertificate(encode(append(leaf, ca...)), encode(key))
		if (err == nil) != tc.ok {
			t.Fatal("incorrect client certificate usage check", err)
		}
	}
}

func TestClientCertificateBoundary(t *testing.T) {
	cert, key := syntheticClientPair(t, nil)
	_, wrongKey := auditCertificate(t)
	encode := base64.StdEncoding.EncodeToString
	c, err := parseConfig([]byte(synthetic))
	if err != nil {
		t.Fatal(err)
	}
	user := namedUser{Name: "cert-user", User: auth{CertData: encode(cert), KeyData: encode(key)}}
	c.Users = append(c.Users, user)
	c.Contexts = append(c.Contexts, namedContext{Name: "cert-context", Context: contextConfig{User: user.Name, Cluster: c.Clusters[0].Name}})
	src, err := serializeConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	p, err := prepare(src, t.TempDir(), t.TempDir(), "/fixture/cli", nil)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := serializeConfig(p.Projection)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(projection, []byte("client-key-data")) || bytes.Contains(projection, key) || bytes.Contains(projection, []byte(user.User.KeyData)) {
		t.Fatal("secret in generated client config")
	}
	if p.Portable.Users[1].User != user.User || len(p.Records[user.Name].Bindings) != 1 {
		t.Fatal("bad portable user or binding")
	}
	r := p.Records[user.Name]
	now := time.Unix(r.Certificate.NotAfter-20, 0)
	status, err := r.execStatus(now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tls.X509KeyPair([]byte(status["clientCertificateData"]), []byte(status["clientKeyData"])); err != nil {
		t.Fatal("invalid returned PEM pair")
	}
	if status["token"] != "" || len(status) != 3 || status["expirationTimestamp"] != now.Add(20*time.Second).UTC().Format(time.RFC3339) {
		t.Fatal("invalid certificate response fields or expiry")
	}
	for _, instant := range []int64{r.Certificate.NotBefore - 1, r.Certificate.NotAfter} {
		if _, err = r.execStatus(now.Add(time.Hour), time.Unix(instant, 0)); err == nil {
			t.Fatal("issued an inactive certificate")
		}
	}
	// Malformed or partial inputs report only the reason, never any private input.
	for _, invalid := range []auth{
		{CertData: user.User.CertData}, {KeyData: user.User.KeyData},
		{KeyData: "synthetic-secret...", CertData: user.User.CertData},
		{KeyData: user.User.KeyData, CertData: "synthetic-secret..."},
		{KeyData: encode(wrongKey), CertData: user.User.CertData},
		{KeyData: encode(append(key, []byte("synthetic-secret")...)), CertData: user.User.CertData},
		{KeyData: user.User.KeyData, CertData: user.User.CertData, Token: "synthetic-secret"},
	} {
		c.Users[1].User = invalid
		data, err := serializeConfig(c)
		if err != nil {
			t.Fatal(err)
		}
		_, err = prepare(data, "/fixture", "/state", "/cli", nil)
		if err == nil || strings.Contains(err.Error(), "synthetic-secret") || strings.Contains(err.Error(), user.User.KeyData) {
			t.Fatal("missing redacted credential error")
		}
	}
}

func TestRepeatedCredentialBudget(t *testing.T) {
	c, err := parseConfig([]byte(synthetic))
	if err != nil {
		t.Fatal(err)
	}
	large := strings.Repeat("x", 250<<10)
	for range 17 {
		c.Users = append(c.Users, namedUser{User: auth{CertData: large}})
	}
	_, err = prepareParsed(c, nil, "/fixture", "/state", "/cli", nil)
	if err == nil || !strings.Contains(err.Error(), "expanded user credentials") {
		t.Fatal("expected aggregate limit before TLS parsing")
	}
}

func TestSetupCheckAndHelp(t *testing.T) {
	dir := privateTemp(t)
	state := filepath.Join(dir, "unused")
	input := filepath.Join(dir, "config")
	sample, err := os.ReadFile("../examples/kubeconfig.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err = writeNew(input, sample); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", input)
	for _, args := range [][]string{{"setup", "--check", input}, {"setup", "--check"}, {"help", "edit"}, {"config", "edit", "--help"}, {"setup", "-h"}, {"--help"}, {"--version"}} {
		if err := run(append([]string{"--state-dir", state}, args...)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = os.Lstat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("check or help created state")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("unexpected side effects")
	}
	got, err := os.ReadFile(input)
	if err != nil || !bytes.Equal(got, sample) {
		t.Fatal("source file changed")
	}
	if err = run([]string{"help", "typo"}); err == nil {
		t.Fatal("unknown help topic accepted")
	}
	var out bytes.Buffer
	if err = printHelp(&out, nil); err != nil || !strings.Contains(out.String(), "setup") || strings.Contains(out.String(), "credential ID") {
		t.Fatal("unexpected overview")
	}
}
