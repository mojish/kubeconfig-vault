package main

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"filippo.io/age"
)

//go:embed web/index.html web/app.js web/style.css
var assets embed.FS

const recipientType = "age-encryption.org/fido2prf"

type stanza struct {
	Type string   `json:"type"`
	Args []string `json:"args"`
	Body []byte   `json:"body"`
}
type browserMessage struct {
	ID       string   `json:"id,omitempty"`
	Step     int      `json:"step,omitempty"`
	Total    int      `json:"total,omitempty"`
	Op       string   `json:"op,omitempty"`
	Identity string   `json:"identity,omitempty"`
	FileKey  []byte   `json:"fileKey,omitempty"`
	Stanzas  []stanza `json:"stanzas,omitempty"`
	Declined bool     `json:"declined,omitempty"`
	Failed   bool     `json:"failed,omitempty"`
}
type approvalPurpose struct {
	Title  string `json:"title"`
	Reason string `json:"reason"`
}

// The helper selects the purpose from the operation it handles. No app identity or
// other label supplied by a client is shown as the source of an approval.
var (
	enrollVaultApproval = approvalPurpose{
		Title:  "Create and verify a YubiKey-protected vault",
		Reason: "These three steps create a vault credential on your security key, encrypt the kubeconfig, and check that the key can open it again.",
	}
	clientUnlockApproval = approvalPurpose{
		Title:  "A Kubernetes client requested vault access",
		Reason: "A program running as your user requested a Kubernetes credential. The vault cannot identify the app. Approving lets local clients request credentials for configured clusters until you lock the vault or the session expires. If this was unexpected, choose Decline request to pause automatic prompts for 10 minutes.",
	}
	manualUnlockApproval = approvalPurpose{
		Title:  "Unlock credentials for this session",
		Reason: "An unlock was requested directly. Approving starts a shared session for local clients until the vault locks or the session expires.",
	}
	openEditApproval = approvalPurpose{
		Title:  "Unlock a plaintext copy for editing",
		Reason: "Approving writes a temporary copy of your kubeconfig that contains its credentials so you can edit it.",
	}
	saveEditApproval = approvalPurpose{
		Title:  "Validate and encrypt your edited kubeconfig",
		Reason: "Approving checks your changes and saves a new encrypted version. After a successful save the vault removes its temporary edit file.",
	}
	exportConfigApproval = approvalPurpose{
		Title:  "Export a new plaintext kubeconfig",
		Reason: "Approving writes the saved kubeconfig and its credentials to the requested output file.",
	}
	verifyLinkApproval = approvalPurpose{
		Title:  "Verify your vault before connecting this kubeconfig",
		Reason: "Approving verifies the existing vault before linking the selected kubeconfig to it.",
	}
	sealOriginalApproval = approvalPurpose{
		Title:  "Encrypt and verify the original kubeconfig for rollback",
		Reason: "Approving protects a copy of the original file so you can restore it when you unlink.",
	}
	verifyOriginalApproval = approvalPurpose{
		Title:  "Verify the original kubeconfig before linking",
		Reason: "Approving checks the existing encrypted rollback copy against the original file before setup continues.",
	}
	restoreOriginalApproval = approvalPurpose{
		Title:  "Restore the original kubeconfig",
		Reason: "Approving restores the exact kubeconfig saved during setup, or verifies that it was already restored.",
	}
	repairLinkApproval = approvalPurpose{
		Title:  "Repair the missing linked kubeconfig",
		Reason: "Approving verifies the encrypted vault before rebuilding the generated client configuration.",
	}
	pruneHistoryApproval = approvalPurpose{
		Title:  "Verify your vault before pruning old generations",
		Reason: "Approving verifies the active vault before the requested older encrypted saves are removed.",
	}
)

type browserPage struct {
	approvalPurpose
	Request *browserMessage `json:"request,omitempty"`
	Done    bool            `json:"done"`
	Success bool            `json:"success"`
}
type ceremony struct {
	ctx           context.Context
	cancel        context.CancelFunc
	detach        func() bool
	server        *http.Server
	mu            sync.Mutex
	page          browserPage
	finalTimer    *time.Timer // protected by mu
	reply         chan browserMessage
	cap           string
	origin        string
	step          int
	total         int
	bootstrap     string
	bootstrapOnce sync.Once
	declined      atomic.Bool
	launchFailed  atomic.Bool
	reached       atomic.Bool
}

func (c *ceremony) removeBootstrap() {
	c.bootstrapOnce.Do(func() {
		if c.bootstrap != "" {
			_ = os.RemoveAll(c.bootstrap)
		}
	})
}

func newCeremony(parent context.Context, purpose approvalPurpose, browser string, steps int) (*ceremony, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	detach := context.AfterFunc(parent, cancel)
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		detach()
		cancel()
		return nil, errors.New("cannot bind browser loopback listener")
	}
	c := &ceremony{ctx: ctx, cancel: cancel, detach: detach, reply: make(chan browserMessage, 1), cap: randomID() + randomID(), page: browserPage{approvalPurpose: purpose}, total: steps}
	c.origin = "http://localhost:" + strings.Split(l.Addr().String(), ":")[1]
	// Only a private file URI goes through process arguments/desktop launch IPC.
	// The browser reads the capability under this user's filesystem permissions.
	c.bootstrap, err = os.MkdirTemp("", "kube-unlock-browser-")
	if err == nil {
		err = writeNew(filepath.Join(c.bootstrap, "open.html"), []byte("<!doctype html><meta name=referrer content=no-referrer><meta http-equiv=refresh content=\"0;url="+c.origin+"/#"+c.cap+"\"><title>Kubeconfig Vault</title>Opening local authentication…"))
	}
	if err != nil {
		c.removeBootstrap()
		l.Close()
		detach()
		cancel()
		return nil, errors.New("cannot create private browser launch file")
	}
	c.server = &http.Server{Handler: http.HandlerFunc(c.serve), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
	go func() { _ = c.server.Serve(l) }()
	go func() { <-ctx.Done(); c.removeBootstrap(); _ = c.server.Close() }()
	if browser == "" {
		if runtime.GOOS == "darwin" {
			browser = "open"
		} else {
			browser = "xdg-open"
		}
	}
	launchURL := (&url.URL{Scheme: "file", Path: filepath.Join(c.bootstrap, "open.html")}).String()
	cmd := exec.Command(browser, launchURL)
	if err = cmd.Start(); err != nil {
		c.removeBootstrap()
		detach()
		cancel()
		return nil, errors.New("cannot launch browser; set --browser to a browser executable")
	}
	go func() {
		if err := cmd.Wait(); err != nil && !c.reached.Load() {
			c.launchFailed.Store(true)
			cancel()
		}
	}()
	return c, nil
}

func (c *ceremony) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	// A private file redirect is a cross-site top-level navigation. It may fetch
	// only the public landing page; API and subresource checks stay unchanged.
	landingNavigation := r.Method == "GET" && r.URL.Path == "/" && r.Header.Get("Origin") == "" && r.Header.Get("Sec-Fetch-Mode") == "navigate" && r.Header.Get("Sec-Fetch-Dest") == "document"
	if r.Host != strings.TrimPrefix(c.origin, "http://") || r.URL.RawQuery != "" || r.Header.Get("Sec-Fetch-Site") == "cross-site" && !landingNavigation {
		http.Error(w, "Forbidden", 403)
		return
	}
	if r.URL.Path == "/api/poll" || r.URL.Path == "/api/reply" {
		if r.Method != "POST" || r.Header.Get("Origin") != c.origin || r.Header.Get("Content-Type") != "application/json" || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Unlock-Capability")), []byte(c.cap)) != 1 {
			http.Error(w, "Forbidden", 403)
			return
		}
		c.reached.Store(true)
		c.removeBootstrap()
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 32768))
		if err != nil {
			http.Error(w, "Too large", 413)
			return
		}
		defer clear(b)
		c.mu.Lock()
		defer c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/poll" {
			if string(b) == `{"displayed":true}` && c.page.Done {
				// A stale poll may have received Done just before a UI action
				// superseded it. Shorten the window only once the page renders it.
				if c.finalTimer != nil {
					c.finalTimer.Reset(1500 * time.Millisecond)
					c.finalTimer = nil
				}
				w.Write([]byte("{}"))
				return
			}
			if string(b) != "{}" {
				http.Error(w, "Invalid request", 400)
				return
			}
			_ = json.NewEncoder(w).Encode(c.page)
			return
		}
		var reply browserMessage
		if decodeJSON(b, &reply) != nil || c.page.Request == nil || reply.ID != c.page.Request.ID {
			http.Error(w, "Stale or invalid request", 409)
			return
		}
		clear(c.page.Request.FileKey)
		c.page.Request = nil
		select {
		case c.reply <- reply:
			w.Write([]byte("{}"))
		default:
			clear(reply.FileKey)
			http.Error(w, "No pending request", 409)
		}
		return
	}
	if r.Method != "GET" || r.Header.Get("Origin") != "" && r.Header.Get("Origin") != c.origin {
		http.Error(w, "Forbidden", 403)
		return
	}
	path := r.URL.Path
	if path == "/" {
		path = "/index.html"
	}
	ct := map[string]string{"/index.html": "text/html; charset=utf-8", "/app.js": "text/javascript; charset=utf-8", "/style.css": "text/css; charset=utf-8"}[path]
	if ct == "" {
		http.NotFound(w, r)
		return
	}
	b, err := assets.ReadFile("web" + path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Write(b)
}

func (c *ceremony) exchange(m browserMessage) (browserMessage, error) {
	m.ID = randomID()
	c.step++
	m.Step, m.Total = c.step, c.total
	m.FileKey = append([]byte(nil), m.FileKey...)
	c.mu.Lock()
	c.page.Request = &m
	c.mu.Unlock()
	defer func() { c.mu.Lock(); clear(m.FileKey); c.page.Request = nil; c.mu.Unlock() }()
	select {
	case <-c.ctx.Done():
		return browserMessage{}, errors.New("browser authentication cancelled or timed out")
	case r := <-c.reply:
		if r.Declined {
			clear(r.FileKey)
			c.declined.Store(true)
			return browserMessage{}, errRequestDeclined
		}
		if r.Failed || c.ctx.Err() != nil {
			clear(r.FileKey)
			return browserMessage{}, errors.New("browser authentication failed or was cancelled")
		}
		return r, nil
	}
}
func (c *ceremony) finish(success bool) {
	c.detach()
	c.mu.Lock()
	if c.page.Request != nil {
		clear(c.page.Request.FileKey)
	}
	c.page.Request = nil
	c.page.Done = true
	c.page.Success = success
	// Background tabs can poll late. At this point only the final status
	// is available. Pending authentication still uses its original timeout.
	c.finalTimer = time.AfterFunc(30*time.Second, c.cancel)
	c.mu.Unlock()
	c.removeBootstrap()
}

type browserKey struct {
	c        *ceremony
	identity string
}

func (b browserKey) Wrap(key []byte) ([]*age.Stanza, error) {
	r, err := b.c.exchange(browserMessage{Op: "wrap", Identity: b.identity, FileKey: key})
	if err != nil {
		return nil, err
	}
	if len(r.Stanzas) != 1 {
		return nil, errors.New("invalid browser recipient count")
	}
	s := r.Stanzas[0]
	if s.Type != recipientType || len(s.Args) != 1 || len(s.Body) != 32 {
		return nil, errors.New("invalid browser stanza")
	}
	n, err := base64.RawStdEncoding.Strict().DecodeString(s.Args[0])
	if err != nil || len(n) != 16 {
		return nil, errors.New("invalid browser nonce")
	}
	return []*age.Stanza{{Type: s.Type, Args: s.Args, Body: s.Body}}, nil
}
func (b browserKey) WrapWithLabels(key []byte) ([]*age.Stanza, []string, error) {
	s, e := b.Wrap(key)
	return s, []string{"postquantum"}, e
}
func (b browserKey) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	var wire []stanza
	for _, s := range stanzas {
		if s.Type == recipientType {
			wire = append(wire, stanza{s.Type, s.Args, s.Body})
		}
	}
	if len(wire) != 1 {
		return nil, age.ErrIncorrectIdentity
	}
	r, err := b.c.exchange(browserMessage{Op: "unwrap", Identity: b.identity, Stanzas: wire})
	if err != nil || len(r.FileKey) != 16 {
		clear(r.FileKey)
		return nil, errors.New("browser unwrapping failed")
	}
	return r.FileKey, nil
}

var errRequestDeclined = errors.New("request declined on the vault page")

func (c *ceremony) failure(err error) error {
	if c.declined.Load() {
		return errRequestDeclined
	}
	if c.launchFailed.Load() {
		return errors.New("browser launcher exited before opening the page; stop the helper and retry with --browser PATH")
	}
	return err
}
