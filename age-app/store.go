package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"filippo.io/age"
	"golang.org/x/sys/unix"
)

const maxVault = 32 << 20

var validID = regexp.MustCompile(`^[a-f0-9]{32}$`)

func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("secure randomness unavailable")
	}
	return hex.EncodeToString(b)
}

func privateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return errors.New("cannot create private directory")
	}
	return checkPrivateDir(path)
}

func checkPrivateDir(path string) error {
	s, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !s.IsDir() || s.Mode().Perm()&0077 != 0 {
		return errors.New("directory must be private (0700) and not a symlink")
	}
	var st unix.Stat_t
	if unix.Lstat(path, &st) != nil || st.Uid != uint32(os.Getuid()) {
		return errors.New("directory must belong to the current user")
	}
	return nil
}

func readBounded(path string, limit int64, private bool) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("cannot open selected file")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size > limit {
		return nil, errors.New("expected a bounded regular file")
	}
	if private && (st.Uid != uint32(os.Getuid()) || st.Mode&0077 != 0 || st.Nlink != 1) {
		return nil, errors.New("private file must be owned by this user, mode 0600, and not hard-linked")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		clear(b)
		return nil, errors.New("file read failed or size limit exceeded")
	}
	return b, nil
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// Never overwrite a user's source or recovery file, including through symlinks.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("output must be a new file in an existing directory")
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return errors.New("output write failed")
	}
	if err = f.Sync(); err != nil {
		return errors.New("output sync failed")
	}
	if err = f.Close(); err != nil {
		return errors.New("output close failed")
	}
	if err = syncDir(filepath.Dir(path)); err != nil {
		return errors.New("output directory sync failed")
	}
	ok = true
	return nil
}

func decodeJSON(data []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return errors.New("invalid metadata or protocol message")
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("unexpected trailing data")
	}
	return nil
}

type snapshot struct {
	ID         string
	Meta       metadata
	Cipher     []byte
	Projection config
}

func currentID(state string) (string, error) {
	target, err := os.Readlink(filepath.Join(state, "current"))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil || !strings.HasPrefix(target, "generations/") || !validID.MatchString(strings.TrimPrefix(target, "generations/")) {
		return "", errors.New("invalid current-generation link")
	}
	return strings.TrimPrefix(target, "generations/"), nil
}

func loadSnapshot(state string) (*snapshot, error) {
	id, err := currentID(state)
	if err != nil {
		return nil, err
	}
	if id == "" {
		return nil, errors.New("no age vault imported")
	}
	return loadGeneration(state, id)
}

func loadGeneration(state, id string) (*snapshot, error) {
	dir := filepath.Join(state, "generations", id)
	if err := privateDir(dir); err != nil {
		return nil, err
	}
	b, err := readBounded(filepath.Join(dir, "metadata.json"), 65536, true)
	if err != nil {
		return nil, err
	}
	s := &snapshot{ID: id}
	if decodeJSON(b, &s.Meta) != nil || s.Meta.Version != 1 || len(s.Meta.Identity) > 16384 || !strings.HasPrefix(s.Meta.Identity, "AGE-PLUGIN-FIDO2PRF-") {
		return nil, errors.New("invalid age vault metadata")
	}
	if _, err = age.ParseHybridRecipient(s.Meta.Recovery); err != nil {
		return nil, errors.New("invalid recovery recipient")
	}
	if s.Cipher, err = readBounded(filepath.Join(dir, "vault.age"), maxVault, true); err != nil {
		return nil, err
	}
	b, err = readBounded(filepath.Join(dir, "kubeconfig"), maxSource, true)
	if err != nil {
		return nil, err
	}
	s.Projection, err = parseConfig(b)
	if err != nil {
		return nil, errors.New("generated kubeconfig is invalid")
	}
	return s, nil
}

func decryptPayload(cipher []byte, identity age.Identity) (*payload, error) {
	r, err := age.Decrypt(bytes.NewReader(cipher), identity)
	if err != nil {
		return nil, errors.New("vault decryption failed")
	}
	b, err := io.ReadAll(io.LimitReader(r, maxVault+1))
	defer clear(b)
	if err != nil || len(b) > maxVault {
		return nil, errors.New("vault authentication or size check failed")
	}
	var p payload
	if decodeJSON(b, &p) != nil || p.Meta.Version != 1 || len(p.Source) > maxSource || len(p.Records) == 0 {
		return nil, errors.New("invalid decrypted vault")
	}
	return &p, nil
}

func encryptPayload(p *payload, recipient age.Recipient) ([]byte, error) {
	recovery, err := age.ParseHybridRecipient(p.Meta.Recovery)
	if err != nil {
		return nil, errors.New("invalid recovery recipient")
	}
	b, err := json.Marshal(p)
	if err != nil || len(b) > maxVault-65536 {
		return nil, errors.New("vault size limit exceeded")
	}
	defer clear(b)
	var out bytes.Buffer
	w, err := age.Encrypt(&out, recipient, recovery)
	if err == nil {
		_, err = w.Write(b)
	}
	if err == nil {
		err = w.Close()
	}
	if err != nil {
		return nil, errors.New("vault encryption failed")
	}
	return out.Bytes(), nil
}

// The caller must authenticate-decrypt the candidate through its recipients first.
func commitSnapshot(state, expected string, p *payload, cipher []byte) (string, error) {
	current, err := currentID(state)
	if err != nil || current != expected {
		return "", errors.New("vault changed; nothing was committed")
	}
	meta, err := json.Marshal(p.Meta)
	if err != nil || len(meta) > 65536 || len(cipher) > maxVault {
		return "", errors.New("generation exceeds the reader size limits")
	}
	projection, err := serializeConfig(p.Projection)
	if err != nil {
		return "", err
	}
	portable, err := serializeConfig(p.Portable)
	clear(portable)
	if err != nil {
		return "", err
	}
	if err = privateDir(filepath.Join(state, "generations")); err != nil {
		return "", err
	}
	id := randomID()
	dir := filepath.Join(state, "generations", id)
	if err = os.Mkdir(dir, 0700); err != nil {
		return "", errors.New("cannot create generation")
	}
	for _, f := range []struct {
		name string
		data []byte
	}{{"vault.age", cipher}, {"metadata.json", meta}, {"kubeconfig", projection}} {
		if err = writeNew(filepath.Join(dir, f.name), f.data); err != nil {
			return "", err
		}
	}
	// Use the same reader as normal unlock before publishing this generation.
	if _, err = loadGeneration(state, id); err != nil {
		return "", errors.New("candidate generation failed its read-back check; current unchanged")
	}
	if err = syncDir(filepath.Join(state, "generations")); err != nil {
		return "", errors.New("generation directory sync failed")
	}
	tmp := filepath.Join(state, ".current-"+randomID())
	if err = os.Symlink("generations/"+id, tmp); err != nil {
		return "", errors.New("cannot create generation link")
	}
	defer os.Remove(tmp)
	if err = os.Rename(tmp, filepath.Join(state, "current")); err != nil {
		return "", errors.New("cannot commit generation")
	}
	if err = syncDir(state); err != nil {
		return id, errors.New("generation switched but directory sync failed; inspect status before retrying")
	}
	return id, nil
}

func readRecovery(path string) (*age.HybridIdentity, error) {
	b, err := readBounded(path, 16384, true)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	return parseRecovery(b)
}

func parseRecovery(b []byte) (*age.HybridIdentity, error) {
	if len(b) > 16384 {
		return nil, errors.New("recovery key is too long")
	}
	i, err := age.ParseHybridIdentity(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, errors.New("invalid hybrid age recovery identity")
	}
	return i, nil
}

// Detach the exact file we checked so an editor's later replacement at the
// original path is never deleted. Editors must be closed before locking: no
// portable filesystem primitive can freeze an uncooperative open write handle.
func (s *service) finalizeEdit(expected []byte, commit func() error) error {
	pending := s.pendingEditPath()
	if _, err := os.Lstat(pending); !errors.Is(err, os.ErrNotExist) {
		return errors.New("an interrupted save already exists; inspect status")
	}
	if err := os.Rename(s.editPath(), pending); err != nil {
		return errors.New("cannot isolate the edit for saving; nothing committed")
	}
	defer func() {
		// Exclusive link avoids overwriting a new editor-created pathname.
		// A crash between link and unlink leaves both copies visible in status.
		if os.Link(pending, s.editPath()) == nil {
			_ = os.Remove(pending)
		}
	}()
	unchanged := func() bool {
		data, err := readBounded(pending, maxSource, true)
		defer clear(data)
		return err == nil && bytes.Equal(data, expected)
	}
	if !unchanged() {
		return errors.New("edit changed during authentication; nothing committed and plaintext preserved; close the editor before retrying")
	}
	if err := commit(); err != nil {
		return err
	}
	if !unchanged() {
		return errors.New("vault saved but edit changed during commit; plaintext preserved; inspect status before retrying")
	}
	if err := os.Remove(pending); err != nil {
		return errors.New("vault saved but plaintext cleanup failed; inspect status")
	}
	if _, err := os.Lstat(s.editPath()); !errors.Is(err, os.ErrNotExist) {
		return errors.New("vault saved but a new edit appeared; plaintext preserved; inspect status before retrying")
	}
	return nil
}

// Publish a complete file exclusively. A crash before the rename leaves
// only a private staging directory and the original destination intact.
func publishNew(path string, data []byte) error {
	dir := filepath.Dir(path)
	stage, err := os.MkdirTemp(dir, ".kubeconfig-vault-stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	file := filepath.Join(stage, "new")
	if err := writeNew(file, data); err != nil {
		return err
	}
	if err := renameNew(file, path); err != nil {
		return err
	}
	return syncDir(dir)
}
