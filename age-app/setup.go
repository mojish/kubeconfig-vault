package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
)

const sealedSuffix = configBackupSuffix + ".age"

// Follow existing aliases, stopping at our managed link. Keep the user's
// original path as the base for relative CA paths, as client-go does.
func clientEntry(state, path string) (string, error) {
	root, err := filepath.EvalSymlinks(state)
	if errors.Is(err, os.ErrNotExist) {
		// Input checks can run before the state directory exists.
		root = state
	} else if err != nil {
		return "", err
	}
	generated := filepath.Join(state, "current", "kubeconfig")
	for i := 0; i < 40; i++ {
		dir, err := filepath.EvalSymlinks(filepath.Dir(path))
		if err != nil {
			return "", errors.New("cannot resolve the client directory")
		}
		path = filepath.Join(dir, filepath.Base(path))
		if pathWithin(root, path) {
			return "", errors.New("select a client config outside the vault directory")
		}
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return path, nil
		}
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || !info.Mode().IsRegular() || st.Nlink != 1 || st.Uid != uint32(os.Getuid()) {
				return "", errors.New("setup requires a user-owned regular file with no hard links")
			}
			return path, nil
		}
		target, err := os.Readlink(path)
		if err != nil || target == generated {
			return path, err
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(dir, target)
		}
		path = target
	}
	return "", errors.New("too many kubeconfig symlinks")
}

func existsEntry(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func withClientLock(path string, change func() error) error {
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("client file is locked or unwritable; finish the concurrent kubeconfig operation first")
	}
	defer os.Remove(path + ".lock")
	if err := f.Close(); err != nil {
		return err
	}
	return change()
}

// Cooperate with writers using either the supplied alias or its target.
func withClientLocks(alias, entry string, change func() error) error {
	dir, err := filepath.EvalSymlinks(filepath.Dir(alias))
	if err != nil {
		return err
	}
	alias = filepath.Join(dir, filepath.Base(alias))
	if alias == entry {
		return withClientLock(entry, change)
	}
	first, second := alias, entry
	if second < first {
		first, second = second, first
	}
	return withClientLock(first, func() error { return withClientLock(second, change) })
}

// Bind the canonical client path to the exact ciphertext verified before activation.
func (s *service) receipt(entry string) string {
	return filepath.Join(s.state, fmt.Sprintf("rollback-%x.sha256", sha256.Sum256([]byte(entry))))
}

const noOriginalReceipt = "no-original-v1\n"

func (s *service) linkReceipt(entry string) (present, noOriginal bool, err error) {
	path := s.receipt(entry)
	if restored, err := existsEntry(path + ".restored"); err != nil {
		return false, false, err
	} else if restored {
		return false, false, errors.New("unfinished unlink; run config unlink for this client to finish cleanup")
	}
	present, err = existsEntry(path)
	if err != nil || !present {
		return
	}
	data, err := readBounded(path, 64, true)
	if err != nil {
		return true, false, err
	}
	if string(data) == noOriginalReceipt {
		return true, true, nil
	}
	if len(data) != sha256.Size {
		return true, false, errors.New("invalid rollback receipt; client preserved")
	}
	return true, false, nil
}
func (s *service) verifyReceipt(entry string, cipher []byte) error {
	return verifyRollbackDigest(s.receipt(entry), cipher)
}

func verifyRollbackDigest(receipt string, cipher []byte) error {
	data, err := readBounded(receipt, 64, true)
	want := sha256.Sum256(cipher)
	if err != nil || !bytes.Equal(data, want[:]) {
		return errors.New("encrypted rollback is missing or changed; client preserved")
	}
	return nil
}
func (s *service) recordRollback(entry string, cipher []byte) error {
	ok, err := existsEntry(s.receipt(entry))
	if err != nil {
		return err
	}
	if !ok {
		sum := sha256.Sum256(cipher)
		if err := publishNew(s.receipt(entry), sum[:]); err != nil {
			return err
		}
	}
	return s.verifyReceipt(entry, cipher)
}

func (s *service) isLinked(path string) bool {
	target, err := os.Readlink(path)
	return err == nil && target == filepath.Join(s.state, "current", "kubeconfig")
}

// Setup may resume between committing the verified generation and switching
// the client. Migration can also resume after writing the encrypted backup.
func (s *service) setup(ctx context.Context, r request) (any, error) {
	path, err := clientEntry(s.state, r.Path)
	if err != nil {
		return nil, err
	}
	id, err := currentID(s.state)
	if err != nil {
		return nil, err
	}
	if id != "" && len(r.RecoveryIdentity) > 0 {
		return nil, errors.New("another setup created the vault first; the recovery key from this attempt was not enrolled")
	}
	linked := s.isLinked(path)
	legacy := path + configBackupSuffix
	oldBackup, err := existsEntry(legacy)
	if err != nil {
		return nil, err
	}
	if oldBackup && !linked {
		return nil, errors.New("an unrelated original backup exists beside this file; setup made no changes")
	}
	source := path
	_, noOriginal, err := s.linkReceipt(path)
	if err != nil {
		return nil, err
	}
	if noOriginal {
		sealed, err := existsEntry(path + sealedSuffix)
		if err != nil {
			return nil, err
		}
		if sealed || oldBackup || id == "" {
			return nil, errors.New("client path conflicts with its no-original receipt; client preserved")
		}
		if linked {
			return "Already set up.", nil
		}
		exists, err := existsEntry(path)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, errors.New("unfinished attachment: run config link --kubeconfig FILE to attach, or config unlink --kubeconfig FILE to clear the receipt")
		}
		return nil, errors.New("client file replaced the managed link; file and receipt preserved")
	}
	if linked {
		if !oldBackup {
			cipher, err := readBounded(path+sealedSuffix, maxVault, true)
			if err != nil || s.verifyReceipt(path, cipher) != nil {
				return nil, errors.New("managed link has no encrypted rollback; locate its original before setup")
			}
			return "Already set up.", nil
		}
		if info, err := os.Lstat(legacy); err != nil || !info.Mode().IsRegular() {
			return nil, errors.New("legacy backup is a symlink or special file; use config unlink to restore the original entry, then run setup")
		}
		source = legacy
	}
	originalInfo, err := os.Lstat(source)
	if err != nil {
		return nil, err
	}
	data, err := readBounded(source, maxSource, linked)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	// Reject unsupported files before asking for approval, including when
	// attaching another file to an existing vault.
	candidate, err := prepare(data, filepath.Dir(r.Path), s.state, s.executable, nil)
	if err != nil {
		return nil, err
	}
	var p *payload
	var cipher []byte
	if id == "" {
		p = candidate
		cipher, err = s.enroll(ctx, r, p)
	} else {
		var snap *snapshot
		p, snap, err = s.open(ctx, "Verify your vault before connecting this kubeconfig")
		if err == nil {
			cipher = snap.Cipher
		}
	}
	if err != nil {
		return nil, err
	}
	// Resolve CA inputs again after authentication, using the enrolled IDs.
	original, err := prepare(data, filepath.Dir(r.Path), s.state, s.executable, p)
	if err != nil {
		return nil, err
	}
	same := original.Source == p.Source && reflect.DeepEqual(original.Portable, p.Portable)
	if !same && !linked && !r.Accept {
		return nil, errors.New("the file or CA differs from the imported source; select the matching file or deliberately attach this one with config link --kubeconfig FILE")
	}
	original.Meta = p.Meta
	sealed := path + sealedSuffix
	prior, err := existsEntry(sealed)
	if err != nil {
		return nil, err
	}
	if prior {
		saved, err := readBounded(sealed, maxVault, true)
		if err != nil {
			return nil, err
		}
		if !same || !bytes.Equal(saved, cipher) {
			check, err := s.openRollback(ctx, saved, p.Meta)
			if err != nil || check.Source != original.Source || !reflect.DeepEqual(check.Portable, original.Portable) {
				return nil, errors.New("existing encrypted rollback differs from this original; both preserved")
			}
		}
		cipher = saved
	} else if !same {
		c, err := newCeremony(ctx, "Encrypt and verify the original kubeconfig for rollback", s.browser, 2)
		if err != nil {
			return nil, err
		}
		key := browserKey{c, p.Meta.Identity}
		cipher, err = encryptPayload(original, key)
		if err == nil {
			var check *payload
			check, err = decryptPayload(cipher, key)
			if err == nil && !samePayload(original, check) {
				err = errors.New("original backup verification failed")
			}
		}
		c.finish(err == nil)
		if err != nil {
			return nil, err
		}
	}
	if err := withClientLocks(r.Path, path, func() error {
		if prior {
			current, err := readBounded(sealed, maxVault, true)
			if err != nil || !bytes.Equal(current, cipher) {
				return errors.New("encrypted rollback changed; retry setup")
			}
		} else if err := publishNew(sealed, cipher); err != nil {
			return err
		}
		verified, err := readBounded(sealed, maxVault, true)
		if err != nil || !bytes.Equal(verified, cipher) {
			return errors.New("encrypted rollback read-back failed; original preserved")
		}
		if err := s.recordRollback(path, cipher); err != nil {
			return err
		}
		entry, err := clientEntry(s.state, r.Path)
		if err != nil || entry != path || s.isLinked(path) != linked {
			return errors.New("client entry changed during setup")
		}
		if have, err := existsEntry(legacy); err != nil || have != linked {
			return errors.New("legacy rollback changed during setup")
		}
		info, err := os.Lstat(source)
		if err != nil || !os.SameFile(originalInfo, info) {
			return errors.New("original replaced during setup; retry")
		}
		latest, err := readBounded(source, maxSource, linked)
		defer clear(latest)
		if err != nil || !bytes.Equal(latest, data) {
			return errors.New("original changed during setup; preserved")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if linked {
			if err := os.Remove(legacy); err != nil {
				return err
			}
		} else if err := replaceClient(path, "", filepath.Join(s.state, "current", "kubeconfig")); err != nil {
			return err
		}
		return syncDir(filepath.Dir(path))
	}); err != nil {
		return nil, err
	}
	return fmt.Sprintf("Ready. Your clients can use %s. Encrypted original: %s", r.Path, sealed), nil
}

func (s *service) openRollback(ctx context.Context, cipher []byte, meta metadata) (*payload, error) {
	c, err := newCeremony(ctx, "Restore the original kubeconfig", s.browser, 1)
	if err != nil {
		return nil, err
	}
	p, err := decryptPayload(cipher, browserKey{c, meta.Identity})
	if err == nil && p.Meta != meta {
		err = errors.New("rollback belongs to a different vault")
	}
	c.finish(err == nil)
	return p, c.failure(err)
}

func replaceClient(path, plaintext, target string) error {
	dir, err := os.MkdirTemp(filepath.Dir(path), ".kubeconfig-vault-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	stage := filepath.Join(dir, "client")
	if target != "" {
		err = os.Symlink(target, stage)
	} else {
		err = writeNew(stage, []byte(plaintext))
	}
	if err != nil {
		return err
	}
	return os.Rename(stage, path)
}

func (s *service) undoSetup(ctx context.Context, alias string) (any, error) {
	path, err := clientEntry(s.state, alias)
	if err != nil {
		return nil, err
	}
	sealed := path + sealedSuffix
	receipt := s.receipt(path)
	completed, err := existsEntry(receipt + ".restored")
	if err != nil {
		return nil, err
	}
	if completed {
		if present, err := existsEntry(receipt); err != nil || present {
			return nil, errors.New("conflicting rollback receipts; files preserved")
		}
		receipt += ".restored"
		present, err := existsEntry(sealed)
		if err != nil {
			return nil, err
		}
		if !present {
			return s.finishUnlinkReceipt(ctx, alias, path)
		}
	}
	cipher, err := readBounded(sealed, maxVault, true)
	if err != nil {
		return nil, err
	}
	if err := verifyRollbackDigest(receipt, cipher); err != nil {
		return nil, err
	}
	// The rollback is independently authenticated. A missing generated client
	// file or active ciphertext need not prevent exact restoration.
	id, err := currentID(s.state)
	if err != nil || id == "" {
		return nil, errors.New("cannot locate the active vault's security-key metadata")
	}
	dir := filepath.Join(s.state, "generations", id)
	for _, parent := range []string{filepath.Dir(dir), dir} {
		if err := checkPrivateDir(parent); err != nil {
			return nil, err
		}
	}
	snap, err := loadMetadata(dir, id)
	if err != nil {
		return nil, err
	}
	p, err := s.openRollback(ctx, cipher, snap.Meta)
	if err != nil {
		return nil, err
	}
	err = withClientLocks(alias, path, func() error {
		entry, err := clientEntry(s.state, alias)
		if err != nil || entry != path {
			return errors.New("client entry changed during restore")
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if present, err := existsEntry(path + configBackupSuffix); err != nil || present {
			return errors.New("finish setup to verify the legacy backup before unlinking")
		}
		current, err := readBounded(sealed, maxVault, true)
		if err != nil || !bytes.Equal(current, cipher) {
			return errors.New("encrypted backup changed")
		}
		if err := verifyRollbackDigest(receipt, current); err != nil {
			return err
		}
		if s.isLinked(path) {
			if completed {
				return errors.New("restored receipt conflicts with a managed link; files preserved")
			}
			if err := replaceClient(path, p.Source, ""); err != nil {
				return err
			}
		} else {
			// A previous run can stop after restoring the original but before
			// removing its ciphertext. Never replace an existing plaintext file.
			if err := syncRestoredClient(path, p.Source); err != nil {
				return err
			}
		}
		if err := syncDir(filepath.Dir(path)); err != nil {
			return err
		}
		if !completed {
			if err := renameNew(receipt, receipt+".restored"); err != nil {
				return errors.New("original restored; could not record cleanup progress")
			}
			receipt += ".restored"
		}
		// Make the completion marker durable before removing the rollback.
		if err := syncDir(s.state); err != nil {
			return err
		}
		if err := os.Remove(sealed); err != nil {
			return errors.New("original restored in plaintext; encrypted backup cleanup failed")
		}
		if err := syncDir(filepath.Dir(path)); err != nil {
			return err
		}
		return removeRestoredReceipt(receipt)
	})
	if err != nil {
		return nil, err
	}
	return "Original kubeconfig restored.", nil
}

// Only the journal entry remains after the original was durably restored and
// its encrypted rollback removed. Do not read or rewrite the client file.
func (s *service) finishUnlinkReceipt(ctx context.Context, alias, path string) (any, error) {
	err := withClientLocks(alias, path, func() error {
		entry, err := clientEntry(s.state, alias)
		if err != nil || entry != path || s.isLinked(path) {
			return errors.New("client path changed; rollback receipt preserved")
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("restored client file is unavailable; rollback receipt preserved")
		}
		receipt := s.receipt(path)
		for _, other := range []string{receipt, path + sealedSuffix, path + configBackupSuffix} {
			if present, err := existsEntry(other); err != nil || present {
				return errors.New("rollback state changed; retry unlink after inspecting the client")
			}
		}
		digest, err := readBounded(receipt+".restored", sha256.Size, true)
		if err != nil || len(digest) != sha256.Size {
			return errors.New("invalid completion receipt; files preserved")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := syncDir(filepath.Dir(path)); err != nil {
			return err
		}
		return removeRestoredReceipt(receipt + ".restored")
	})
	if err != nil {
		return nil, err
	}
	return "Finished cleanup from the previous restore. The client file was left in place.", nil
}

// A writer may have saved identical bytes without syncing them. Flush the
// descriptor we verified before giving up the encrypted rollback.
func syncRestoredClient(path, original string) error {
	f, err := openBounded(path, maxSource, true)
	if err != nil {
		return errors.New("cannot verify restored client; client and encrypted rollback preserved")
	}
	defer f.Close()
	existing, err := io.ReadAll(io.LimitReader(f, maxSource+1))
	defer clear(existing)
	if err != nil || len(existing) > maxSource || !bytes.Equal(existing, []byte(original)) {
		return errors.New("client differs from the verified original; client and encrypted rollback preserved")
	}
	if err := f.Sync(); err != nil {
		return errors.New("could not sync restored client; encrypted rollback preserved")
	}
	opened, err := f.Stat()
	current, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !os.SameFile(opened, current) {
		return errors.New("restored client changed during verification; encrypted rollback preserved")
	}
	return nil
}

func removeRestoredReceipt(receipt string) error {
	if err := os.Remove(receipt); err != nil {
		return errors.New("original restored in plaintext; rollback receipt cleanup failed")
	}
	if err := syncDir(filepath.Dir(receipt)); err != nil {
		return errors.New("original restored and receipt removed; final cleanup could not be synced to disk")
	}
	return nil
}
