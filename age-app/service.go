package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
	"gopkg.in/yaml.v3"
)

type request struct {
	Keep             int      `json:"keep,omitempty"`
	Op               string   `json:"op"`
	Path             string   `json:"path,omitempty"`
	Recovery         string   `json:"recovery,omitempty"`
	RecoveryIdentity []byte   `json:"recovery_identity,omitempty"`
	ID               string   `json:"id,omitempty"`
	Cluster          *cluster `json:"cluster,omitempty"`
	Accept           bool     `json:"accept,omitempty"`
}
type response struct {
	Error  string `json:"error,omitempty"`
	Result any    `json:"result,omitempty"`
}
type session struct {
	Generation   string
	Records      map[string]record
	Projection   config
	Deadline     time.Time
	WallDeadline time.Time
}
type service struct {
	state, executable, browser string
	ttl                        time.Duration
	op                         sync.Mutex
	mu                         sync.Mutex
	cache                      *session
	epoch                      uint64
	active                     context.CancelFunc
	closed                     bool
	retryAfter                 time.Time // accessed under the operation mutex
	stop                       chan struct{}
}

func (s *service) clearSession() { s.mu.Lock(); s.cache = nil; s.mu.Unlock() }
func (s *service) expireLocked() {
	if s.cache != nil && (!time.Now().Before(s.cache.Deadline) || !time.Now().Round(0).Before(s.cache.WallDeadline)) {
		s.cache = nil
	}
}
func (s *service) editPath() string        { return filepath.Join(s.state, "edit", "kubeconfig") }
func (s *service) pendingEditPath() string { return filepath.Join(s.state, "edit", "saving") }
func (s *service) editPaths() []string {
	var paths []string
	for _, path := range []string{s.editPath(), s.pendingEditPath()} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			paths = append(paths, path)
		}
	}
	return paths
}
func (s *service) status() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	paths := s.editPaths()
	edit := len(paths) != 0
	result := map[string]any{"unlocked": s.cache != nil, "edit_open": edit, "fully_locked": s.cache == nil && !edit, "kubeconfig": filepath.Join(s.state, "current", "kubeconfig")}
	if edit {
		result["edit_path"] = paths[0]
		result["edit_paths"] = paths
	}
	if s.cache != nil {
		result["expires_at"] = s.cache.WallDeadline.UTC().Format(time.RFC3339)
	}
	return result
}
func (s *service) lock(stop bool) map[string]any {
	s.mu.Lock()
	s.epoch++
	s.cache = nil
	if s.active != nil {
		s.active()
	}
	if stop {
		s.closed = true
	}
	s.mu.Unlock()
	// Wait until any cancelled plaintext operation has unwound before reporting.
	s.op.Lock()
	defer s.op.Unlock()
	return s.status()
}

func (s *service) handle(parent context.Context, r request) (any, error) {
	if r.Op == "status" {
		return s.status(), nil
	}
	if r.Op == "lock" || r.Op == "stop" {
		result := s.lock(r.Op == "stop")
		if r.Op == "stop" {
			time.AfterFunc(100*time.Millisecond, func() {
				select {
				case <-s.stop:
				default:
					close(s.stop)
				}
			})
		}
		return result, nil
	}
	s.mu.Lock()
	epoch := s.epoch
	s.mu.Unlock()
	s.op.Lock()
	defer s.op.Unlock()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	s.mu.Lock()
	if s.closed || epoch != s.epoch || ctx.Err() != nil {
		s.mu.Unlock()
		return nil, errors.New("operation cancelled by lock or stop")
	}
	s.active = cancel
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.active = nil; s.mu.Unlock() }()
	switch r.Op {
	case "credential":
		return s.credential(ctx, epoch, r)
	case "prune":
		return s.prune(ctx, r.Keep)
	case "restore":
		return s.restoreBackup(ctx, r)
	case "setup":
		return s.setup(ctx, r)
	case "undo-setup":
		return s.undoSetup(ctx, r.Path)
	case "import":
		return s.importConfig(ctx, r)
	case "unlock":
		p, snap, err := s.open(ctx, "Unlock credentials for this session")
		if err != nil {
			return nil, err
		}
		if err = s.cachePayload(epoch, p, snap.ID); err != nil {
			return nil, err
		}
		return s.status(), nil
	case "config-unlock":
		if len(s.editPaths()) != 0 {
			return nil, errors.New("an edit already exists; save or discard it first")
		}
		p, snap, err := s.open(ctx, "Unlock a plaintext copy for editing")
		if err != nil {
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, errors.New("operation cancelled")
		}
		if err = privateDir(filepath.Dir(s.editPath())); err != nil {
			return nil, err
		}
		marker := filepath.Join(s.state, "edit", "generation")
		if err = os.Remove(marker); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("cannot remove previous edit marker")
		}
		if err = writeNew(marker, []byte(snap.ID)); err != nil {
			return nil, err
		}
		if err = writeNew(s.editPath(), []byte(p.Source)); err != nil {
			return nil, err
		}
		return s.status(), nil
	case "config-lock":
		return s.saveEdit(ctx, r.Accept)
	case "config-discard":
		s.clearSession()
		for _, path := range s.editPaths() {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, errors.New("cannot delete plaintext edit")
			}
		}
		_ = os.Remove(filepath.Join(s.state, "edit", "generation"))
		return s.status(), nil
	case "export":
		p, _, err := s.open(ctx, "Export a new plaintext kubeconfig")
		if err != nil {
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, errors.New("operation cancelled")
		}
		b, err := yaml.Marshal(p.Portable)
		if err != nil {
			return nil, errors.New("cannot serialize portable config")
		}
		defer clear(b)
		if err = writeNew(r.Path, b); err != nil {
			return nil, err
		}
		return map[string]string{"plaintext_file": r.Path}, nil
	default:
		return nil, errors.New("unsupported operation")
	}
}

func (s *service) open(ctx context.Context, title string) (*payload, *snapshot, error) {
	snap, err := loadSnapshot(s.state)
	if err != nil {
		return nil, nil, err
	}
	c, err := newCeremony(ctx, title, s.browser, 1)
	if err != nil {
		return nil, nil, err
	}
	ok := false
	defer func() { c.finish(ok) }()
	p, err := decryptPayload(snap.Cipher, browserKey{c, snap.Meta.Identity})
	if err != nil {
		return nil, nil, err
	}
	if p.Meta != snap.Meta || !equalProjection(p.Projection, snap.Projection) {
		return nil, nil, errors.New("vault metadata or generated connection settings changed")
	}
	if ctx.Err() != nil {
		return nil, nil, errors.New("operation cancelled")
	}
	ok = true
	return p, snap, nil
}

func samePayload(a, b *payload) bool { return reflect.DeepEqual(a, b) }
func (s *service) prepareImport(source string) (*payload, error) {
	id, err := currentID(s.state)
	if err != nil {
		return nil, err
	}
	if id != "" {
		return nil, errors.New("this state directory already has a vault; choose a new directory")
	}
	data, err := readBounded(source, maxSource, false)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	return prepare(data, filepath.Dir(source), s.state, s.executable, nil)
}

func (s *service) importConfig(ctx context.Context, r request) (any, error) {
	p, err := s.prepareImport(r.Path)
	if err != nil {
		return nil, err
	}
	if _, err := s.enroll(ctx, r, p); err != nil {
		return nil, err
	}
	return s.status(), nil
}

func (s *service) enroll(ctx context.Context, r request, p *payload) ([]byte, error) {
	recovery, err := requestRecovery(r)
	if err != nil {
		return nil, err
	}
	c, err := newCeremony(ctx, "Create and verify a YubiKey-protected vault", s.browser, 3)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() { c.finish(ok) }()
	m, err := c.exchange(browserMessage{Op: "enroll"})
	if err != nil {
		return nil, c.failure(err)
	}
	if len(m.Identity) > 16384 || !strings.HasPrefix(m.Identity, "AGE-PLUGIN-FIDO2PRF-1") {
		return nil, errors.New("invalid browser identity")
	}
	p.Meta = metadata{Version: 1, Identity: m.Identity, Recovery: recovery.Recipient().String()}
	key := browserKey{c, p.Meta.Identity}
	cipher, err := encryptPayload(p, key)
	if err != nil {
		return nil, err
	}
	verified, err := decryptPayload(cipher, key)
	if err != nil || !samePayload(p, verified) {
		return nil, errors.New("YubiKey verification failed; no vault committed")
	}
	verified, err = decryptPayload(cipher, recovery)
	if err != nil || !samePayload(p, verified) {
		return nil, errors.New("recovery verification failed; no vault committed")
	}
	if ctx.Err() != nil {
		return nil, errors.New("operation cancelled")
	}
	if _, err = commitSnapshot(s.state, "", p, cipher); err != nil {
		return nil, err
	}
	s.clearSession()
	ok = true
	return cipher, nil
}

func (s *service) saveEdit(ctx context.Context, accept bool) (any, error) {
	if _, err := os.Lstat(s.pendingEditPath()); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("an interrupted save remains; review edit_paths in status and preserve or discard the files before retrying")
	}
	b, err := readBounded(s.editPath(), maxSource, true)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	marker, err := readBounded(filepath.Join(s.state, "edit", "generation"), 128, true)
	if err != nil {
		return nil, err
	}
	snap, err := loadSnapshot(s.state)
	if err != nil {
		return nil, err
	}
	if string(marker) != snap.ID {
		return nil, errors.New("edit belongs to another generation; export or preserve it before recovery")
	}
	c, err := newCeremony(ctx, "Validate and encrypt your edited kubeconfig", s.browser, 3)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() { c.finish(ok) }()
	key := browserKey{c, snap.Meta.Identity}
	old, err := decryptPayload(snap.Cipher, key)
	if err != nil {
		return nil, c.failure(err)
	}
	if old.Meta != snap.Meta || !equalProjection(old.Projection, snap.Projection) {
		return nil, errors.New("vault metadata or generated settings changed")
	}
	p, err := prepare(b, old.Base, s.state, s.executable, old)
	if err != nil {
		return nil, err
	}
	migrateCommandName(&old.Projection, s.executable)
	if !accept && !equalProjection(old.Projection, p.Projection) {
		return nil, errors.New("connection, trust, or user mapping changed; review the edit then use --accept-connection-changes")
	}
	p.Meta = old.Meta
	preserveSelections(old, p, snap.Projection)
	cipher, err := encryptPayload(p, key)
	if err != nil {
		return nil, err
	}
	verified, err := decryptPayload(cipher, key)
	if err != nil || !samePayload(p, verified) {
		return nil, errors.New("candidate verification failed; edit and previous vault preserved")
	}
	if ctx.Err() != nil {
		return nil, errors.New("operation cancelled")
	}
	// Invalidate credentials even if the commit's final directory sync fails.
	s.clearSession()
	if err = s.finalizeEdit(b, func() error {
		_, commitErr := commitSnapshot(s.state, snap.ID, p, cipher)
		return commitErr
	}); err != nil {
		return nil, err
	}
	_ = os.Remove(filepath.Join(s.state, "edit", "generation"))
	ok = true
	return s.status(), nil
}

func (s *service) cachePayload(epoch uint64, p *payload, generation string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.epoch != epoch || s.closed {
		return errors.New("unlock cancelled")
	}
	now := time.Now()
	s.cache = &session{Generation: generation, Records: p.Records, Projection: p.Projection, Deadline: now.Add(s.ttl), WallDeadline: now.Round(0).Add(s.ttl)}
	return nil
}

func tokenDeadline(token string, deadline time.Time) time.Time {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return deadline
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(b) > 65536 {
		return deadline
	}
	defer clear(b)
	var claims struct {
		Exp json.Number `json:"exp"`
	}
	if json.Unmarshal(b, &claims) != nil || claims.Exp == "" {
		return deadline
	}
	seconds, err := strconv.ParseInt(string(claims.Exp), 10, 64)
	if err != nil {
		return deadline
	}
	expires := time.Unix(seconds, 0)
	if expires.Before(deadline) {
		return expires
	}
	return deadline
}
func (s *service) credential(ctx context.Context, epoch uint64, r request) (any, error) {
	if r.Cluster == nil || !validID.MatchString(r.ID) || r.Cluster.CAFile != "" || r.Cluster.Insecure {
		return nil, errors.New("exec request needs an approved cluster and credential ID")
	}
	snap, err := loadSnapshot(s.state)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.expireLocked()
	cached := s.cache
	if cached != nil && (cached.Generation != snap.ID || !equalProjection(cached.Projection, snap.Projection)) {
		s.cache = nil
		s.mu.Unlock()
		return nil, errors.New("connection settings changed; refusing cached credentials")
	}
	s.mu.Unlock()
	if cached == nil {
		if time.Now().Before(s.retryAfter) {
			return nil, errors.New("browser unlock cooldown; run unlock explicitly to retry now")
		}
		p, current, err := s.open(ctx, "Unlock Kubernetes access")
		if err != nil {
			if ctx.Err() == nil {
				s.retryAfter = time.Now().Add(30 * time.Second)
			}
			return nil, err
		}
		if err = s.cachePayload(epoch, p, current.ID); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	cached = s.cache
	if cached == nil || s.epoch != epoch {
		return nil, errors.New("session expired or locked")
	}
	for _, rec := range cached.Records {
		if rec.ID == r.ID {
			for _, approved := range rec.Bindings {
				if approved == binding(*r.Cluster) {
					deadline := tokenDeadline(rec.Token, cached.WallDeadline)
					if !time.Now().Round(0).Before(deadline) {
						return nil, errors.New("Kubernetes token has expired; update the source credential")
					}
					return map[string]any{"apiVersion": "client.authentication.k8s.io/v1", "kind": "ExecCredential", "status": map[string]string{"token": rec.Token, "expirationTimestamp": deadline.UTC().Format(time.RFC3339)}}, nil
				}
			}
		}
	}
	return nil, errors.New("credential is not approved for this cluster and TLS configuration")
}

func recoverFile(cipherPath, keyPath, out string) error {
	key, err := readRecovery(keyPath)
	if err != nil {
		return err
	}
	return recoverWithKey(cipherPath, out, key)
}

func recoverWithKey(cipherPath, out string, key *age.HybridIdentity) error {
	p, err := readRecovered(cipherPath, key)
	if err != nil {
		return err
	}
	if out == "" {
		fmt.Fprintln(os.Stdout, "Recovery verified.")
		return nil
	}
	b, err := yaml.Marshal(p.Portable)
	if err != nil {
		return errors.New("cannot serialize recovered config")
	}
	defer clear(b)
	return writeNew(out, b)
}

func createRecovery(path string) error {
	identity, err := age.GenerateHybridIdentity()
	if err != nil {
		return errors.New("cannot generate recovery key")
	}
	return writeNew(path, []byte(identity.String()+"\n"))
}

func readRecovered(cipherPath string, key *age.HybridIdentity) (*payload, error) {
	cipher, err := readBounded(cipherPath, maxVault, false)
	if err != nil {
		return nil, err
	}
	p, err := decryptPayload(cipher, key)
	if err != nil {
		return nil, err
	}
	// Trust the authenticated payload, not possibly damaged outside metadata.
	if p.Meta.Recovery != key.Recipient().String() {
		return nil, errors.New("recovery recipient does not match authenticated vault")
	}
	for _, entry := range p.Portable.Clusters {
		if entry.Cluster.CAFile != "" {
			return nil, errors.New("portable backup contains an external CA path")
		}
	}
	data, err := serializeConfig(p.Portable)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	if _, err := prepare(data, "", "", "", nil); err != nil {
		return nil, errors.New("backup does not contain a supported portable kubeconfig")
	}
	return p, nil
}

func requestRecovery(r request) (*age.HybridIdentity, error) {
	if len(r.RecoveryIdentity) != 0 {
		if r.Recovery != "" {
			return nil, errors.New("select one recovery key source")
		}
		return parseRecovery(r.RecoveryIdentity)
	}
	return readRecovery(r.Recovery)
}

func (s *service) restoreBackup(ctx context.Context, r request) (any, error) {
	if id, err := currentID(s.state); err != nil || id != "" {
		return nil, errors.New("restore requires an unused vault directory")
	}
	key, err := requestRecovery(r)
	if err != nil {
		return nil, err
	}
	old, err := readRecovered(r.Path, key)
	if err != nil {
		return nil, err
	}
	data, err := serializeConfig(old.Portable)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	p, err := prepare(data, filepath.Dir(r.Path), s.state, s.executable, nil)
	if err != nil {
		return nil, err
	}
	// Enroll with exactly the identity that authenticated the backup.
	r.Recovery = ""
	r.RecoveryIdentity = []byte(key.String())
	defer clear(r.RecoveryIdentity)
	if _, err := s.enroll(ctx, r, p); err != nil {
		return nil, err
	}
	return "Vault restored. Run config link to connect your clients.", nil
}
