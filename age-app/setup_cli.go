package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func setupPath(args []string) (string, error) {
	if len(args) == 1 && args[0] != "" {
		return absolute(args[0])
	}
	if len(args) != 0 {
		return "", errors.New("usage: setup [KUBECONFIG_FILE]")
	}
	paths := filepath.SplitList(os.Getenv("KUBECONFIG"))
	switch len(paths) {
	case 0:
		return defaultKubeconfigPath()
	case 1:
		return absolute(paths[0])
	default:
		return "", errors.New("KUBECONFIG selects multiple files; run setup FILE with one inline-token kubeconfig")
	}
}

func (s *service) startSetup(path string) error {
	entry, err := clientEntry(s.state, path)
	if err != nil {
		return err
	}
	if entry != path {
		fmt.Fprintf(os.Stderr, "Setup will replace the file at %s. Existing aliases including %s will follow the vault.\n", entry, path)
	} else {
		fmt.Fprintln(os.Stderr, "Setting up", entry)
	}
	r := request{Op: "setup", Path: path}
	id, err := currentID(s.state)
	if err != nil {
		return err
	}
	if id == "" {
		data, err := readBounded(entry, maxSource, false)
		if err != nil {
			return err
		}
		defer clear(data)
		if _, err = prepare(data, filepath.Dir(path), s.state, s.executable, nil); err != nil {
			return err
		}
		if present, err := existsEntry(entry + configBackupSuffix); err != nil || present {
			return errors.New("original backup already exists; locate its vault before setup")
		}
		if present, err := existsEntry(entry + sealedSuffix); err != nil || present {
			return errors.New("encrypted rollback already exists; locate its vault before setup")
		}
		r.RecoveryIdentity, err = showNewRecoveryKey()
		if err != nil {
			return err
		}
		defer clear(r.RecoveryIdentity)
	}
	return s.clientAction(r)
}

func (s *service) clientAction(r request) error {
	result, err := s.rpc(r)
	if err != nil {
		if err.Error() == "unsupported operation" {
			return errors.New("an older helper is running; run kube-unlock-age stop and retry")
		}
		return err
	}
	var msg string
	if err := json.Unmarshal(result, &msg); err != nil {
		return errors.New("unexpected helper response")
	}
	fmt.Fprintln(os.Stdout, msg)
	return nil
}

func (s *service) clientLink(action string, args []string) error {
	path, err := setupPath(nil)
	if len(args) == 2 && args[0] == "--kubeconfig" {
		path, err = absolute(args[1])
	} else if len(args) != 0 {
		return errors.New("expected --kubeconfig FILE")
	}
	if err != nil {
		return err
	}
	if action == "link" {
		if _, err := loadSnapshot(s.state); err != nil {
			return errors.New("no valid vault; run setup first")
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
	}
	entry, err := clientEntry(s.state, path)
	if err != nil {
		return err
	}
	sealed, err := existsEntry(entry + sealedSuffix)
	if err != nil {
		return err
	}
	record, err := existsEntry(s.receipt(entry))
	if err != nil {
		return err
	}
	if record && !sealed {
		return errors.New("the encrypted rollback is missing; client preserved")
	}
	if action == "unlink" && sealed {
		if !s.isLinked(entry) {
			return errors.New("file is not linked to this vault; encrypted backup preserved")
		}
		return s.clientAction(request{Op: "undo-setup", Path: path})
	}
	if action == "link" {
		exists, err := existsEntry(entry)
		if err != nil {
			return err
		}
		if !exists && sealed {
			return errors.New("an encrypted rollback already exists; client path is missing")
		}
		if exists {
			if s.isLinked(entry) && !sealed {
				legacy, err := existsEntry(entry + configBackupSuffix)
				if err != nil {
					return err
				}
				if !legacy {
					fmt.Fprintln(os.Stdout, "Already linked.")
					return nil
				}
			}
			return s.clientAction(request{Op: "setup", Path: path, Accept: true})
		}
	}
	// Compatibility with old plaintext rollback and links with no original.
	return withClientLocks(path, entry, func() error {
		actual, err := clientEntry(s.state, path)
		if err != nil || actual != entry {
			return errors.New("client path changed; retry")
		}
		if action == "unlink" {
			if !s.isLinked(entry) {
				return errors.New("client file is not linked to this vault")
			}
			if present, err := existsEntry(entry + sealedSuffix); err != nil || present {
				return errors.New("rollback changed; retry unlink")
			}
			return restoreConfigLink(entry, entry+configBackupSuffix)
		}
		for _, suffix := range []string{"", configBackupSuffix, sealedSuffix} {
			if present, err := existsEntry(entry + suffix); err != nil || present {
				return errors.New("client file or rollback already exists")
			}
		}
		if err := os.Symlink(filepath.Join(s.state, "current", "kubeconfig"), entry); err != nil {
			return err
		}
		return syncDir(filepath.Dir(entry))
	})
}
