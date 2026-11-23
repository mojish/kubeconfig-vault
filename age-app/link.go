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

func pathWithin(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
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
