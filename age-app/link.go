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

// Restore only the saved entry. If the backup disappears before the rename,
// the rename fails and the client link stays in place.
func restoreLegacyConfigLink(path string) error {
	backup := path + configBackupSuffix
	info, err := os.Lstat(backup)
	if err != nil || (!info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0) {
		return errors.New("legacy rollback is missing or invalid; client preserved")
	}
	if err := os.Rename(backup, path); err != nil {
		return errors.New("could not restore the legacy backup; client preserved")
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		return errors.New("legacy original restored, but directory sync failed")
	}
	fmt.Fprintf(os.Stdout, "Restored %s\n", path)
	return nil
}
