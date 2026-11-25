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

const ageHeader = "age-encryption.org/v1\n"

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
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0077 != 0 {
		return errors.New("directory must be private (0700) and not a symlink")
	}
	if st.Uid != uint32(os.Getuid()) {
		return errors.New("directory must belong to the current user")
	}
	return nil
}

func openBounded(path string, limit int64, private bool) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("cannot open selected file")
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size > limit {
		f.Close()
		return nil, errors.New("expected a bounded regular file")
	}
	if private && (st.Uid != uint32(os.Getuid()) || st.Mode&0077 != 0 || st.Nlink != 1) {
		f.Close()
		return nil, errors.New("private file must be owned by this user, mode 0600, and not hard-linked")
	}
	return f, nil
}

func readBounded(path string, limit int64, private bool) ([]byte, error) {
	f, err := openBounded(path, limit, private)
	if err != nil {
		return nil, err
	}
	defer f.Close()
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

// A read-only preflight avoids prompting for a destination that is already
// unusable. The final write still opens the output exclusively.
func checkNewOutput(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return errors.New("output already exists; choose a new filename")
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot inspect the output path")
	}
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil || !dir.IsDir() {
		return errors.New("output directory must already exist")
	}
	return nil
}

// Only inspect the public format marker before asking for a private recovery
// key. The ordinary decrypt path authenticates the entire selected backup.
func checkBackupInput(path string) error {
	f, err := openBounded(path, maxVault, false)
	if err != nil {
		return errors.New("cannot open the backup; select an age vault file")
	}
	defer f.Close()
	var header [len(ageHeader)]byte
	if _, err := io.ReadFull(f, header[:]); err != nil || string(header[:]) != ageHeader {
		return errors.New("selected file is not an age vault backup")
	}
	return nil
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

func activeGeneration(state string) (string, error) {
	id, err := currentID(state)
	if err != nil {
		return "", err
	}
	if id == "" {
		return "", errors.New("no active vault generation; run kubeconfig-vault status")
	}
	return id, nil
}

func loadSnapshot(state string) (*snapshot, error) {
	id, err := activeGeneration(state)
	if err != nil {
		return nil, err
	}
	return loadGeneration(state, id)
}

func currentCiphertext(state string) ([]byte, error) {
	id, err := activeGeneration(state)
	if err != nil {
		return nil, err
	}
	// Resolve current once. A concurrent save publishes another directory,
	// while an opened file remains readable even if its generation is pruned.
	dir := filepath.Join(state, "generations", id)
	for _, path := range []string{state, filepath.Dir(dir), dir} {
		if err := checkPrivateDir(path); err != nil {
			return nil, err
		}
	}
	cipher, err := readBounded(filepath.Join(dir, "vault.age"), maxVault, true)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(cipher, []byte(ageHeader)) {
		return nil, errors.New("selected generation has no age ciphertext header")
	}
	return cipher, nil
}

func backupGeneration(state, out string) error {
	cipher, err := currentCiphertext(state)
	if err != nil {
		return err
	}
	return publishNew(out, cipher)
}

func compareBackup(state, path string) error {
	cipher, err := currentCiphertext(state)
	if err != nil {
		return err
	}
	backup, err := readBounded(path, maxVault, false)
	if err != nil {
		return err
	}
	if !bytes.HasPrefix(backup, []byte(ageHeader)) {
		return errors.New("selected file is not an age vault backup")
	}
	if !bytes.Equal(backup, cipher) {
		return errors.New("backup differs from the current encrypted save")
	}
	return nil
}

func loadGeneration(state, id string) (*snapshot, error) {
	s, err := loadGenerationSettings(state, id)
	if err != nil {
		return nil, err
	}
	if err := s.readCipher(state); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *snapshot) readCipher(state string) error {
	if _, err := age.ParseHybridRecipient(s.Meta.Recovery); err != nil {
		return errors.New("invalid recovery recipient")
	}
	var err error
	s.Cipher, err = readBounded(filepath.Join(state, "generations", s.ID, "vault.age"), maxVault, true)
	return err
}

func loadMetadata(dir, id string) (*snapshot, error) {
	b, err := readBounded(filepath.Join(dir, "metadata.json"), 65536, true)
	if err != nil {
		return nil, err
	}
	s := &snapshot{ID: id}
	if decodeJSON(b, &s.Meta) != nil || s.Meta.Version != 1 || len(s.Meta.Identity) > 16384 || !strings.HasPrefix(s.Meta.Identity, "AGE-PLUGIN-FIDO2PRF-") {
		return nil, errors.New("invalid age vault metadata")
	}
	return s, nil
}

func loadGenerationSettings(state, id string) (*snapshot, error) {
	s, b, err := readGenerationSettings(state, id)
	if err != nil {
		return nil, err
	}
	s.Projection, err = parseConfig(b)
	if err != nil {
		return nil, errors.New("generated kubeconfig is invalid")
	}
	return s, nil
}

func readGenerationSettings(state, id string) (*snapshot, []byte, error) {
	dir := filepath.Join(state, "generations", id)
	if err := checkPrivateDir(dir); err != nil {
		return nil, nil, err
	}
	s, err := loadMetadata(dir, id)
	if err != nil {
		return nil, nil, err
	}
	b, err := readBounded(filepath.Join(dir, "kubeconfig"), maxSource, true)
	return s, b, err
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
func (s *service) finalizeEdit(expected []byte, outcome string, commit func() error) error {
	if err := checkPrivateDir(filepath.Dir(s.editPath())); err != nil {
		return err
	}
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
		return errors.New(outcome + " but edit changed during finalization; plaintext preserved; inspect status before retrying")
	}
	if err := os.Remove(pending); err != nil {
		return errors.New(outcome + " but plaintext cleanup failed; inspect status")
	}
	if _, err := os.Lstat(s.editPath()); !errors.Is(err, os.ErrNotExist) {
		return errors.New(outcome + " but a new edit appeared; plaintext preserved; inspect status before retrying")
	}
	return nil
}

// Publish a complete file exclusively. A crash before the rename leaves
// only a private staging directory and the original destination intact.
func publishNew(path string, data []byte) error {
	return publishNewChecked(path, data, nil)
}

func publishNewChecked(path string, data []byte, check func() error) error {
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
	if check != nil {
		if err := check(); err != nil {
			return err
		}
	}
	if err := renameNew(file, path); err != nil {
		return err
	}
	if err := syncDir(dir); err != nil {
		return errors.New("file published but directory sync failed; inspect the destination before retrying")
	}
	return nil
}
