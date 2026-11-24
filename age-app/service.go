package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
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
	Meta         metadata
	Records      map[string]record
	Projection   config
	Deadline     time.Time
	WallDeadline time.Time
}

// Constructed only after authenticating the vault for config-unlock. The
// operation mutex protects this in-memory record throughout the edit.
type editBaseline struct {
	generation         string
	source, ciphertext [sha256.Size]byte
	meta               metadata
	projection         config
	recordIDs          map[string]record
	base               string
}

func authenticatedEdit(p *payload, snap *snapshot) *editBaseline {
	ids := make(map[string]record, len(p.Records))
	for name, r := range p.Records {
		ids[name] = record{ID: r.ID}
	}
	return &editBaseline{
		generation: snap.ID, source: sha256.Sum256([]byte(p.Source)),
		ciphertext: sha256.Sum256(snap.Cipher), meta: p.Meta,
		projection: managed(p.Projection), recordIDs: ids, base: p.Base,
	}
}

type service struct {
	state, executable, browser string
	ttl                        time.Duration
	op                         sync.Mutex
	mu                         sync.Mutex
	cache                      *session
	edit                       *editBaseline
	epoch                      uint64
	active                     context.CancelFunc
	closed                     bool
	retryAfter                 time.Time // protected by mu
	stop                       chan struct{}
	stopOnce                   sync.Once
}

func (s *service) clearSession() { s.mu.Lock(); s.cache = nil; s.mu.Unlock() }
func (s *service) expireLocked() {
	if s.cache != nil && (!time.Now().Before(s.cache.Deadline) || !time.Now().Round(0).Before(s.cache.WallDeadline)) {
		s.cache = nil
	}
}
func (s *service) editPath() string        { return filepath.Join(s.state, "edit", "kubeconfig") }
func (s *service) pendingEditPath() string { return filepath.Join(s.state, "edit", "saving") }
func (s *service) editPaths() ([]string, error) {
	if err := checkPrivateDir(filepath.Dir(s.editPath())); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, errors.New("cannot safely inspect the plaintext edit directory")
	}
	var paths []string
	for _, path := range []string{s.editPath(), s.pendingEditPath()} {
		if _, err := os.Lstat(path); err == nil {
			paths = append(paths, path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return paths, errors.New("cannot determine whether plaintext edits exist")
		}
	}
	return paths, nil
}
func (s *service) status() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	paths, editErr := s.editPaths()
	edit := len(paths) != 0
	result := map[string]any{"unlocked": s.cache != nil, "edit_open": edit, "fully_locked": s.cache == nil && !edit && editErr == nil, "kubeconfig": filepath.Join(s.state, "current", "kubeconfig")}
	if editErr != nil {
		result["problems"] = []string{editErr.Error()}
	}
	if time.Now().Before(s.retryAfter) {
		result["automatic_unlock_paused_until"] = s.retryAfter.UTC().Format(time.RFC3339Nano)
	}
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
	s.edit = nil
	return s.status()
}

func (s *service) handle(parent context.Context, r request) (any, error) {
	if r.Op == "status" {
		return s.status(), nil
	}
	if r.Op == "lock" || r.Op == "stop" {
		result := s.lock(r.Op == "stop")
		if r.Op == "stop" {
			s.stopOnce.Do(func() {
				time.AfterFunc(100*time.Millisecond, func() { close(s.stop) })
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
		if paths, err := s.editPaths(); err != nil {
			return nil, err
		} else if len(paths) != 0 {
			return nil, errors.New("an edit already exists; save or discard it first")
		}
		s.edit = nil
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
		s.edit = authenticatedEdit(p, snap)
		return s.status(), nil
	case "config-repair":
		return s.repair(ctx, r.Path)
	case "config-lock":
		return s.saveEdit(ctx, r.Accept)
	case "config-discard":
		s.edit = nil
		s.clearSession()
		if _, err := os.Lstat(filepath.Dir(s.editPath())); errors.Is(err, os.ErrNotExist) {
			return s.status(), nil
		}
		paths, err := s.editPaths()
		if err != nil {
			return nil, err
		}
		for _, path := range paths {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, errors.New("cannot delete plaintext edit")
			}
		}
		if err := s.finishEditCleanup(); err != nil {
			return nil, err
		}
		return s.status(), nil
	case "export":
		if err := checkNewOutput(r.Path); err != nil {
			return nil, err
		}
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
	p, err := s.authenticateSnapshot(ctx, title, snap)
	return p, snap, err
}

func (s *service) authenticateSnapshot(ctx context.Context, title string, snap *snapshot) (*payload, error) {
	c, err := newCeremony(ctx, title, s.browser, 1)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() { c.finish(ok) }()
	p, err := decryptPayload(snap.Cipher, browserKey{c, snap.Meta.Identity})
	if err != nil {
		return nil, c.failure(err)
	}
	if p.Meta != snap.Meta || !equalProjection(p.Projection, snap.Projection) {
		return nil, errors.New("vault metadata or generated connection settings changed")
	}
	if ctx.Err() != nil {
		return nil, errors.New("operation cancelled")
	}
	ok = true
	return p, nil
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

// An unchanged source can still refer to a different CA on disk. Reuse the
// ordinary preparation path to resolve those files and derive the exact
// settings a full save would publish, including the installed command path.
func (s *service) unchangedEdit(b []byte, snap *snapshot) bool {
	e := s.edit
	if e == nil || snap.ID != e.generation || snap.Meta != e.meta ||
		sha256.Sum256(b) != e.source || sha256.Sum256(snap.Cipher) != e.ciphertext ||
		!equalProjection(e.projection, snap.Projection) {
		return false
	}
	next, err := prepare(b, e.base, s.state, s.executable, &payload{Records: e.recordIDs})
	return err == nil && equalProjection(e.projection, next.Projection)
}

// Both plaintext names and the generation marker live in this directory.
// Flush their removals together before reporting successful cleanup.
func (s *service) finishEditCleanup() error {
	dir := filepath.Dir(s.editPath())
	markerErr := os.Remove(filepath.Join(dir, "generation"))
	if err := syncDir(dir); err != nil {
		return errors.New("could not make edit cleanup durable; check storage and retry config discard after inspecting status")
	}
	if markerErr != nil && !errors.Is(markerErr, os.ErrNotExist) {
		return errors.New("could not remove the edit generation marker; inspect the edit directory")
	}
	return nil
}

func (s *service) editSaved(changed bool) (map[string]any, error) {
	s.edit = nil
	if err := s.finishEditCleanup(); err != nil {
		if changed {
			return nil, fmt.Errorf("vault saved but cleanup incomplete: %w", err)
		}
		return nil, err
	}
	result := s.status()
	result["changed"] = changed
	return result, nil
}

func (s *service) saveEdit(ctx context.Context, accept bool) (any, error) {
	if err := checkPrivateDir(filepath.Dir(s.editPath())); err != nil {
		return nil, err
	}
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
	if s.unchangedEdit(b, snap) {
		s.clearSession()
		err = s.finalizeEdit(b, "vault unchanged", func() error {
			current, err := loadSnapshot(s.state)
			if err != nil {
				return err
			}
			if !s.unchangedEdit(b, current) {
				return errors.New("vault or connection settings changed while closing; plaintext edit preserved")
			}
			return ctx.Err()
		})
		if err != nil {
			return nil, err
		}
		return s.editSaved(false)
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
	if err = s.finalizeEdit(b, "vault saved", func() error {
		_, commitErr := commitSnapshot(s.state, snap.ID, p, cipher)
		return commitErr
	}); err != nil {
		return nil, err
	}
	ok = true
	return s.editSaved(true)
}

func (s *service) cachePayload(epoch uint64, p *payload, generation string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.epoch != epoch || s.closed {
		return errors.New("unlock cancelled")
	}
	s.retryAfter = time.Time{}
	now := time.Now()
	s.cache = &session{Generation: generation, Meta: p.Meta, Records: p.Records, Projection: p.Projection, Deadline: now.Add(s.ttl), WallDeadline: now.Round(0).Add(s.ttl)}
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

// Validate the files that select and describe the authenticated generation on
// every delivery. Only a fresh authentication needs the ciphertext bytes.
func (s *service) checkCachedGeneration(cached *session) error {
	id, err := currentID(s.state)
	if err != nil {
		return err
	}
	if cached.Generation != id {
		return errors.New("vault generation changed; refusing cached credentials")
	}
	settings, err := loadGenerationSettings(s.state, id)
	if err != nil {
		return err
	}
	if cached.Meta != settings.Meta || !equalProjection(cached.Projection, settings.Projection) {
		return errors.New("vault metadata or connection settings changed; refusing cached credentials")
	}
	cipher, err := openBounded(filepath.Join(s.state, "generations", id, "vault.age"), maxVault, true)
	if err != nil {
		return err
	}
	return cipher.Close()
}

func retryDeadline(now time.Time, err error) time.Time {
	if errors.Is(err, errRequestDeclined) {
		return now.Add(10 * time.Minute)
	}
	return now.Add(30 * time.Second)
}

func automaticPause(now, until time.Time) error {
	if !now.Before(until) {
		return nil
	}
	return fmt.Errorf("automatic unlock paused until %s; run kubeconfig-vault unlock to retry now", until.UTC().Format(time.RFC3339Nano))
}

var errCredentialBinding = errors.New("credential is not approved for this cluster and TLS configuration")

// The readable client config can rule out a stale request before opening a
// browser. Only the records from the authenticated vault can authorize delivery.
func (c config) referencesCredential(id string, requested cluster) bool {
	var user string
	for _, u := range c.Users {
		e := u.User.Exec
		if e != nil && len(e.Args) >= 2 && e.Args[len(e.Args)-2] == "credential" && e.Args[len(e.Args)-1] == id {
			user = u.Name
			break
		}
	}
	if user == "" {
		return false
	}
	names := make(map[string]bool)
	for _, entry := range c.Clusters {
		if entry.Cluster == requested {
			names[entry.Name] = true
		}
	}
	for _, entry := range c.Contexts {
		if entry.Context.User == user && names[entry.Context.Cluster] {
			return true
		}
	}
	return false
}

func boundRecord(records map[string]record, id, clusterBinding string) (record, error) {
	for _, rec := range records {
		if rec.ID == id && slices.Contains(rec.Bindings, clusterBinding) {
			return rec, nil
		}
	}
	return record{}, errCredentialBinding
}

func (s *service) credential(ctx context.Context, epoch uint64, r request) (any, error) {
	if r.Cluster == nil || !validID.MatchString(r.ID) || r.Cluster.CAFile != "" || r.Cluster.Insecure {
		return nil, errors.New("exec request needs an approved cluster and credential ID")
	}
	s.mu.Lock()
	s.expireLocked()
	cached, retryAfter := s.cache, s.retryAfter
	s.mu.Unlock()
	requestedBinding := binding(*r.Cluster)
	if cached == nil {
		if err := automaticPause(time.Now(), retryAfter); err != nil {
			return nil, err
		}
		current, err := loadSnapshot(s.state)
		if err != nil {
			return nil, err
		}
		if !current.Projection.referencesCredential(r.ID, *r.Cluster) {
			return nil, errCredentialBinding
		}
		p, err := s.authenticateSnapshot(ctx, "A Kubernetes client requested vault access", current)
		if err != nil {
			if ctx.Err() == nil {
				now := time.Now()
				deadline := retryDeadline(now, err)
				s.mu.Lock()
				s.retryAfter = deadline
				s.mu.Unlock()
				return nil, fmt.Errorf("%w: %v", err, automaticPause(now, deadline))
			}
			return nil, err
		}
		if _, err := boundRecord(p.Records, r.ID, requestedBinding); err != nil {
			return nil, err
		}
		if err = s.cachePayload(epoch, p, current.ID); err != nil {
			return nil, err
		}
		s.mu.Lock()
		cached = s.cache
		s.mu.Unlock()
	}
	if cached == nil {
		return nil, errors.New("session expired or locked")
	}
	if err := s.checkCachedGeneration(cached); err != nil {
		s.clearSession()
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	cached = s.cache
	if cached == nil || s.epoch != epoch {
		return nil, errors.New("session expired or locked")
	}
	rec, err := boundRecord(cached.Records, r.ID, requestedBinding)
	if err != nil {
		return nil, err
	}
	status, err := rec.execStatus(cached.WallDeadline, time.Now())
	if err != nil {
		return nil, err
	}
	return map[string]any{"apiVersion": "client.authentication.k8s.io/v1", "kind": "ExecCredential", "status": status}, nil
}

// Client-go retains a delivered token until this timestamp, independently of the helper.
func credentialDeadline(token string, sessionEnd, now time.Time) time.Time {
	clientEnd := now.Add(time.Minute)
	if sessionEnd.Before(clientEnd) {
		clientEnd = sessionEnd
	}
	return tokenDeadline(token, clientEnd)
}

func recoverFile(cipherPath, keyPath, out string) error {
	if out != "" {
		if err := checkNewOutput(out); err != nil {
			return err
		}
	}
	var key *age.HybridIdentity
	var err error
	if keyPath == "" {
		if err := checkBackupInput(cipherPath); err != nil {
			return err
		}
		key, err = promptRecoveryKey()
	} else {
		key, err = readRecovery(keyPath)
	}
	if err != nil {
		return err
	}
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
	// Validate the authenticated portable data using the legacy input contract
	// for private recovery. restoreBackup separately calls prepare before it
	// publishes a new readable client file.
	c, err := parseConfig(data)
	if err != nil {
		return nil, err
	}
	if _, err := prepareParsed(c, data, "", "", "", nil); err != nil {
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
