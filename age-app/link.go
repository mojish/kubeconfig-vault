package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const configBackupSuffix = ".before-kubeconfig-vault"

func defaultKubeconfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("cannot resolve home directory")
	}
	return filepath.Join(home, ".kube", "config"), nil
}

func configureKubeconfigLink(state, action string, args []string) error {
	var path string
	var err error
	switch {
	case len(args) == 0:
		path, err = defaultKubeconfigPath()
	case len(args) == 2 && args[0] == "--kubeconfig":
		path, err = absolute(args[1])
	default:
		return errors.New("usage: config link|unlink [--kubeconfig FILE]")
	}
	if err != nil {
		return err
	}
	generated := filepath.Join(state, "current", "kubeconfig")
	if pathWithin(state, path) {
		return errors.New("the client kubeconfig must be outside the vault directory")
	}
	if action == "link" {
		if generation, err := currentID(state); err != nil || generation == "" {
			return errors.New("no valid vault at this state directory; run import first")
		}
		if info, err := os.Lstat(generated); err != nil || !info.Mode().IsRegular() {
			return errors.New("the vault's generated kubeconfig is missing or invalid")
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return errors.New("cannot create the client kubeconfig directory")
		}
	}
	// Check canonical directories as well, while keeping the leaf entry intact.
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return errors.New("cannot resolve the client kubeconfig directory")
	}
	if actualState, err := filepath.EvalSymlinks(state); err == nil && pathWithin(actualState, filepath.Join(parent, filepath.Base(path))) {
		return errors.New("the client kubeconfig must be outside the vault directory")
	}
	return changeConfigLink(path, generated, action == "link")
}

func pathWithin(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func changeConfigLink(path, generated string, link bool) error {
	// Match client-go's config lock so kubectl config writes cannot race this change.
	lock, err := os.OpenFile(path+".lock", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot lock the client kubeconfig; check permissions or finish any concurrent edit")
	}
	_ = lock.Close()
	defer os.Remove(path + ".lock")
	backup := path + configBackupSuffix
	old, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot inspect the client kubeconfig entry")
	}
	currentLink, _ := os.Readlink(path)
	if !link {
		if currentLink != generated {
			return errors.New("client kubeconfig is not linked to this vault; no change made")
		}
		return restoreConfigLink(path, backup)
	}
	if currentLink == generated {
		fmt.Fprintf(os.Stdout, "Already linked: %s\n", path)
		return nil
	}
	if _, err := os.Lstat(backup); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("backup path already exists or is inaccessible: %s", backup)
	}
	return activateConfigLink(path, generated, backup, old)
}

func activateConfigLink(path, generated, backup string, old os.FileInfo) error {
	dir := filepath.Dir(path)
	stage, err := os.MkdirTemp(dir, ".kubeconfig-vault-link-")
	if err != nil {
		return errors.New("cannot prepare the client kubeconfig link")
	}
	defer os.RemoveAll(stage)
	link := filepath.Join(stage, "config")
	if err := os.Symlink(generated, link); err != nil {
		return errors.New("cannot prepare the client kubeconfig link")
	}
	committed := false
	if old != nil {
		if err := backupConfigEntry(path, backup, old.Mode()); err != nil {
			return err
		}
		defer func() {
			if !committed {
				_ = os.Remove(backup)
			}
		}()
		if err := syncDir(dir); err != nil {
			return errors.New("could not sync the original kubeconfig backup; link not installed")
		}
	}
	current, err := os.Lstat(path)
	if old == nil && !errors.Is(err, os.ErrNotExist) || old != nil &&
		(err != nil || !os.SameFile(old, current) || !old.ModTime().Equal(current.ModTime()) || old.Size() != current.Size()) {
		return errors.New("the client kubeconfig changed while linking; no replacement made")
	}
	if err := os.Rename(link, path); err != nil {
		return errors.New("could not install the client kubeconfig link")
	}
	committed = true
	fmt.Fprintf(os.Stdout, "Linked %s to %s\n", path, generated)
	if old != nil {
		fmt.Fprintf(os.Stdout, "Original saved at %s\n", backup)
	}
	if err := syncDir(dir); err != nil {
		return errors.New("kubeconfig linked but directory sync failed")
	}
	return nil
}

func backupConfigEntry(path, backup string, mode os.FileMode) error {
	switch {
	case mode.IsRegular():
		data, err := readBounded(path, maxSource, false)
		if err != nil {
			return errors.New("cannot back up the original kubeconfig")
		}
		defer clear(data)
		return writeNew(backup, data)
	case mode&os.ModeSymlink != 0:
		target, err := os.Readlink(path)
		if err != nil || os.Symlink(target, backup) != nil {
			return errors.New("cannot back up the original kubeconfig symlink")
		}
		return nil
	default:
		return errors.New("original kubeconfig must be a regular file or a symlink")
	}
}

func restoreConfigLink(path, backup string) error {
	info, err := os.Lstat(backup)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.Remove(path); err != nil {
			return errors.New("could not remove the client kubeconfig link")
		}
		fmt.Fprintf(os.Stdout, "Removed %s. No local original was available to restore.\n", path)
	case err != nil || (!info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0):
		return errors.New("invalid client kubeconfig backup; no change made")
	default:
		if err := os.Rename(backup, path); err != nil {
			return errors.New("could not restore the original client kubeconfig")
		}
		fmt.Fprintf(os.Stdout, "Restored %s\n", path)
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		return errors.New("kubeconfig link removed but directory sync failed")
	}
	return nil
}
