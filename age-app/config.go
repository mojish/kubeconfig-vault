package main

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

const maxSource = 4 << 20

type cluster struct {
	Server        string `json:"server" yaml:"server"`
	CA            string `json:"certificate-authority-data,omitempty" yaml:"certificate-authority-data,omitempty"`
	CAFile        string `json:"certificate-authority,omitempty" yaml:"certificate-authority,omitempty"`
	Insecure      bool   `json:"insecure-skip-tls-verify,omitempty" yaml:"insecure-skip-tls-verify,omitempty"`
	TLSName       string `json:"tls-server-name,omitempty" yaml:"tls-server-name,omitempty"`
	Proxy         string `json:"proxy-url,omitempty" yaml:"proxy-url,omitempty"`
	NoCompression bool   `json:"disable-compression,omitempty" yaml:"disable-compression,omitempty"`
}
type execConfig struct {
	APIVersion  string       `json:"apiVersion" yaml:"apiVersion"`
	Command     string       `json:"command" yaml:"command"`
	Args        []string     `json:"args" yaml:"args"`
	Interactive string       `json:"interactiveMode" yaml:"interactiveMode"`
	ClusterInfo bool         `json:"provideClusterInfo" yaml:"provideClusterInfo"`
	Env         emptyExecEnv `json:"-" yaml:"env,omitempty"`
}

// client-go writes env: null even when no environment overrides exist.
type emptyExecEnv struct{}

var errExecEnv = errors.New("users[].user.exec.env must be empty in a generated kubeconfig; setup requires inline bearer tokens")

func (*emptyExecEnv) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.SequenceNode && len(n.Content) == 0 {
		return nil
	}
	return errExecEnv
}

type auth struct {
	Token string      `json:"token,omitempty" yaml:"token,omitempty"`
	Exec  *execConfig `json:"exec,omitempty" yaml:"exec,omitempty"`
}
type namedCluster struct {
	Name    string  `json:"name" yaml:"name"`
	Cluster cluster `json:"cluster" yaml:"cluster"`
}
type namedUser struct {
	Name string `json:"name" yaml:"name"`
	User auth   `json:"user" yaml:"user"`
}
type contextConfig struct {
	Cluster   string `json:"cluster" yaml:"cluster"`
	User      string `json:"user" yaml:"user"`
	Namespace string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
}
type namedContext struct {
	Name    string        `json:"name" yaml:"name"`
	Context contextConfig `json:"context" yaml:"context"`
}
type config struct {
	APIVersion  string         `json:"apiVersion" yaml:"apiVersion"`
	Kind        string         `json:"kind" yaml:"kind"`
	Clusters    []namedCluster `json:"clusters" yaml:"clusters"`
	Users       []namedUser    `json:"users" yaml:"users"`
	Contexts    []namedContext `json:"contexts" yaml:"contexts"`
	Current     string         `json:"current-context,omitempty" yaml:"current-context,omitempty"`
	Preferences map[string]any `json:"preferences,omitempty" yaml:"preferences,omitempty"`
}
type record struct {
	ID       string   `json:"id"`
	Token    string   `json:"token"`
	Bindings []string `json:"bindings"`
}
type metadata struct {
	Version  int    `json:"version"`
	Identity string `json:"identity"`
	Recovery string `json:"recovery"`
}
type payload struct {
	Meta       metadata          `json:"metadata"`
	Source     string            `json:"source"`
	Base       string            `json:"base"`
	Records    map[string]record `json:"records"`
	Projection config            `json:"projection"`
	Portable   config            `json:"portable"`
}

func parseConfig(data []byte) (config, error) {
	var c config
	if len(data) > maxSource {
		return c, errors.New("kubeconfig exceeds the size limit")
	}
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	if err := d.Decode(&c); err != nil {
		return c, configDecodeError(err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return c, errors.New("expected one YAML document")
	}
	if c.APIVersion != "v1" || c.Kind != "Config" {
		return c, errors.New("expected a Kubernetes v1 Config")
	}
	return c, nil
}

func configDecodeError(err error) error {
	if errors.Is(err, errExecEnv) {
		return errExecEnv
	}
	// The YAML decoder includes input values in some errors. Only report
	// field names from the allowlist, including when the input is malformed.
	var fields *yaml.TypeError
	if errors.As(err, &fields) {
		for _, detail := range fields.Errors {
			if strings.HasSuffix(detail, " not found in type main.execConfig") {
				return errors.New("unsupported users[].user.exec configuration; setup requires inline bearer tokens")
			}
			for _, field := range []string{"tokenFile", "auth-provider", "client-certificate", "client-certificate-data", "client-key", "client-key-data", "username", "password"} {
				if strings.HasSuffix(detail, ": field "+field+" not found in type main.auth") {
					return fmt.Errorf("users[].user.%s is unsupported; select a kubeconfig with inline bearer tokens", field)
				}
			}
		}
	}
	return errors.New("invalid or unsupported kubeconfig YAML")
}
func binding(c cluster) string {
	c.CAFile = ""
	b, _ := json.Marshal(c)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func managed(c config) config {
	c.Current = ""
	c.Preferences = nil
	// Kubernetes writes named entries in its own order. Keep the original
	// arrays intact for editing, including the positional exec arguments.
	c.Clusters = slices.Clone(c.Clusters)
	c.Users = slices.Clone(c.Users)
	c.Contexts = slices.Clone(c.Contexts)
	slices.SortFunc(c.Clusters, func(a, b namedCluster) int { return cmp.Compare(a.Name, b.Name) })
	slices.SortFunc(c.Users, func(a, b namedUser) int { return cmp.Compare(a.Name, b.Name) })
	slices.SortFunc(c.Contexts, func(a, b namedContext) int { return cmp.Compare(a.Name, b.Name) })
	for i := range c.Contexts {
		c.Contexts[i].Context.Namespace = ""
	}
	return c
}

// Decode one exact certificate block at a time. pem.Decode alone can skip
// unrelated or malformed input before a later valid block.
func publicCertificates(data []byte) ([]byte, error) {
	const begin = "-----BEGIN CERTIFICATE-----"
	const end = "-----END CERTIFICATE-----"
	var out bytes.Buffer
	for rest := bytes.TrimSpace(data); len(rest) != 0; {
		stop := bytes.Index(rest, []byte(end))
		if !bytes.HasPrefix(rest, []byte(begin)) || stop < 0 {
			return nil, errors.New("CA data must contain only public certificate PEM blocks")
		}
		encoded := rest[:stop+len(end)]
		block, extra := pem.Decode(encoded)
		if block == nil || len(extra) != 0 || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || bytes.Count(encoded, []byte("-----BEGIN ")) != 1 {
			return nil, errors.New("invalid public certificate PEM block")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("invalid public certificate")
		}
		out.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
		rest = bytes.TrimSpace(rest[len(encoded):])
	}
	if out.Len() == 0 {
		return nil, errors.New("CA data must contain a public certificate")
	}
	return out.Bytes(), nil
}

func serializeConfig(c config) ([]byte, error) {
	b, err := yaml.Marshal(c)
	if err != nil {
		return nil, errors.New("cannot serialize config")
	}
	if _, err = parseConfig(b); err != nil {
		clear(b)
		return nil, errors.New("generated or portable config exceeds supported format or size limits")
	}
	return b, nil
}

func prepare(source []byte, base, state, executable string, previous *payload) (*payload, error) {
	c, err := parseConfig(source)
	if err != nil {
		return nil, err
	}
	if err := validateProjectionProxies(c); err != nil {
		return nil, err
	}
	return prepareParsed(c, source, base, state, executable, previous)
}

// A generated client file stores proxy-url in readable form. Older encrypted
// backups may contain a query or fragment and must still support private export.
func validateProjectionProxies(c config) error {
	for _, n := range c.Clusters {
		if strings.ContainsAny(n.Cluster.Proxy, "?#") {
			return errors.New("clusters[].cluster.proxy-url is copied into the client file; remove the query or fragment before setup or save")
		}
	}
	return nil
}

func prepareParsed(c config, source []byte, base, state, executable string, previous *payload) (*payload, error) {
	// Legacy preferences belong in Source only. They may carry opaque
	// extension data that must not reach a generated client file.
	c.Preferences = nil
	if len(c.Clusters) == 0 || len(c.Users) == 0 || len(c.Contexts) == 0 {
		return nil, errors.New("clusters, token users, and contexts are required")
	}
	clusters, users, contexts := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i := range c.Clusters {
		n := &c.Clusters[i]
		if n.Name == "" || clusters[n.Name] {
			return nil, errors.New("duplicate or empty cluster name")
		}
		clusters[n.Name] = true
		v := &n.Cluster
		u, e := url.Parse(v.Server)
		if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, errors.New("cluster server must be an HTTPS URL without credentials, query, or fragment")
		}
		if v.Insecure {
			return nil, errors.New("insecure-skip-tls-verify is not supported by this backend")
		}
		if v.Proxy != "" {
			u, e = url.Parse(v.Proxy)
			if e != nil || u.User != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http" && u.Scheme != "socks5") {
				return nil, errors.New("clusters[].cluster.proxy-url must be an HTTP, HTTPS, or SOCKS5 URL without user credentials")
			}
		}
		if v.CAFile != "" {
			if v.CA != "" {
				return nil, errors.New("choose one CA source")
			}
			path := v.CAFile
			if !filepath.IsAbs(path) {
				path = filepath.Join(base, path)
			}
			ca, e := readBounded(path, maxSource, false)
			if e != nil {
				return nil, errors.New("unable to read selected CA file")
			}
			v.CA = base64.StdEncoding.EncodeToString(ca)
			clear(ca)
			v.CAFile = ""
		}
		if v.CA != "" {
			ca, e := base64.StdEncoding.DecodeString(v.CA)
			if e != nil {
				return nil, errors.New("invalid public CA certificate data")
			}
			public, e := publicCertificates(ca)
			clear(ca)
			if e != nil {
				return nil, e
			}
			v.CA = base64.StdEncoding.EncodeToString(public)
		}
	}
	p := &payload{Source: string(source), Base: base, Records: map[string]record{}}
	for _, n := range c.Users {
		if n.Name == "" || users[n.Name] {
			return nil, errors.New("duplicate or empty user name")
		}
		users[n.Name] = true
		if n.User.Exec != nil {
			return nil, errors.New("users[].user.exec is unsupported as an import source; select a kubeconfig with inline bearer tokens")
		}
		if n.User.Token == "" || len(n.User.Token) > 65536 || strings.ContainsAny(n.User.Token, "\r\n") {
			return nil, errors.New("only nonempty inline bearer-token users are supported")
		}
		id := randomID()
		if previous != nil {
			if old, ok := previous.Records[n.Name]; ok {
				id = old.ID
			}
		}
		p.Records[n.Name] = record{ID: id, Token: n.User.Token}
	}
	for _, n := range c.Contexts {
		if n.Name == "" || contexts[n.Name] || !clusters[n.Context.Cluster] || !users[n.Context.User] {
			return nil, errors.New("duplicate context or invalid cluster/user reference")
		}
		contexts[n.Name] = true
		r := p.Records[n.Context.User]
		for _, c := range c.Clusters {
			if c.Name == n.Context.Cluster {
				r.Bindings = append(r.Bindings, binding(c.Cluster))
			}
		}
		p.Records[n.Context.User] = r
	}
	if c.Current != "" && !contexts[c.Current] {
		return nil, errors.New("current context does not exist")
	}
	p.Portable = c
	p.Projection = c
	p.Projection.Contexts = append([]namedContext(nil), c.Contexts...)
	p.Projection.Users = make([]namedUser, 0, len(c.Users))
	for _, n := range c.Users {
		p.Projection.Users = append(p.Projection.Users, namedUser{Name: n.Name, User: auth{Exec: &execConfig{
			APIVersion: "client.authentication.k8s.io/v1", Command: executable,
			Args: []string{"--state-dir", state, "credential", p.Records[n.Name].ID}, Interactive: "Never", ClusterInfo: true,
		}}})
	}
	for _, generated := range []config{p.Projection, p.Portable} {
		b, err := serializeConfig(generated)
		clear(b)
		if err != nil {
			return nil, err
		}
	}
	return p, nil
}
func preserveSelections(old, next *payload, observed config) {
	before, _ := parseConfig([]byte(old.Source))
	after, _ := parseConfig([]byte(next.Source))
	if before.Current == after.Current {
		next.Projection.Current = ""
		for _, n := range next.Projection.Contexts {
			if n.Name == observed.Current {
				next.Projection.Current = observed.Current
			}
		}
	}
	for i := range next.Projection.Contexts {
		n := &next.Projection.Contexts[i]
		for _, original := range before.Contexts {
			if original.Name == n.Name && original.Context.Namespace == n.Context.Namespace {
				for _, selected := range observed.Contexts {
					if selected.Name == n.Name {
						n.Context.Namespace = selected.Context.Namespace
					}
				}
			}
		}
	}
}
func equalProjection(a, b config) bool { return reflect.DeepEqual(managed(a), managed(b)) }
