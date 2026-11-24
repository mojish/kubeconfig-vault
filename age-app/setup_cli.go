package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func setupPath(args []string) (string, error) {
	if len(args) == 1 && args[0] != "" {
		return absolute(args[0])
	}
	if len(args) != 0 {
		return "", errors.New("usage: setup [KUBECONFIG_FILE]")
	}
	list := os.Getenv("KUBECONFIG")
	if list == "" {
		return defaultKubeconfigPath()
	}
	var selected string
	for _, p := range filepath.SplitList(list) {
		if p == "" {
			continue
		}
		path, err := absolute(p)
		if err != nil {
			return "", err
		}
		if selected != "" && selected != path {
			return "", errors.New("KUBECONFIG selects multiple files; set it to one file or pass the client path explicitly")
		}
		selected = path
	}
	if selected == "" {
		return "", errors.New("KUBECONFIG contains no file paths; set it to one file or pass the client path explicitly")
	}
	return selected, nil
}

func (s *service) setupCommand(args []string) error {
	const usage = "usage: setup [FILE] [--check | --recovery-key KEYFILE]"
	var file []string
	var recovery string
	var check bool
	for i := 0; i < len(args); i++ {
		switch arg := args[i]; arg {
		case "--check":
			if check {
				return errors.New(usage)
			}
			check = true
		case "--recovery-key":
			i++
			if recovery != "" || i == len(args) || args[i] == "" || strings.HasPrefix(args[i], "--") {
				return errors.New(usage)
			}
			recovery = args[i]
		default:
			if len(file) != 0 || arg == "" || strings.HasPrefix(arg, "--") {
				return errors.New(usage)
			}
			file = []string{arg}
		}
	}
	if check && recovery != "" {
		return errors.New(usage)
	}
	path, err := setupPath(file)
	if err != nil {
		return err
	}
	if check {
		entry, err := clientEntry(s.state, path)
		if err != nil {
			return err
		}
		if s.isLinked(entry) {
			return errors.New("client already linked; use kubeconfig-vault status")
		}
		if err := s.validateInput(path, entry); err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, "Supported kubeconfig. No files changed.")
		return nil
	}
	return s.startSetup(path, recovery)
}

func (s *service) validateInput(path, entry string) error {
	data, err := readBounded(entry, maxSource, false)
	if err != nil {
		return err
	}
	defer clear(data)
	_, err = prepare(data, filepath.Dir(path), s.state, s.executable, nil)
	return err
}

func (s *service) startSetup(path, recoveryFile string) error {
	if err := s.checkSocketPath(); err != nil {
		return err
	}
	if err := checkPrivateDir(s.state); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
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
		if err := s.validateInput(path, entry); err != nil {
			return err
		}
		if present, err := existsEntry(entry + configBackupSuffix); err != nil || present {
			return errors.New("original backup already exists; locate its vault before setup")
		}
		if present, err := existsEntry(entry + sealedSuffix); err != nil || present {
			return errors.New("encrypted rollback already exists; locate its vault before setup")
		}
		if recoveryFile == "" {
			r.RecoveryIdentity, err = showNewRecoveryKey()
			if err != nil {
				return err
			}
		} else {
			key, err := readRecovery(recoveryFile)
			if err != nil {
				return err
			}
			r.RecoveryIdentity = []byte(key.String())
		}
		defer clear(r.RecoveryIdentity)
	} else if recoveryFile != "" {
		return errors.New("this vault already has a recovery key; to resume setup, omit --recovery-key")
	}
	if err := s.clientAction(r); err != nil {
		return err
	}
	if len(r.RecoveryIdentity) != 0 {
		fmt.Fprintln(os.Stdout, "Security key verified. This vault credential is non-discoverable in Yubico Authenticator.")
	}
	return nil
}

func (s *service) clientAction(r request) error {
	result, err := s.rpc(r)
	if err != nil {
		if err.Error() == "unsupported operation" {
			return errors.New("an older helper is running; run kubeconfig-vault stop and retry")
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
	if action == "repair" {
		return s.clientAction(request{Op: "config-repair", Path: path})
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
	if action == "unlink" {
		completed, err := existsEntry(s.receipt(entry) + ".restored")
		if err != nil {
			return err
		}
		if completed {
			return s.clientAction(request{Op: "undo-setup", Path: path})
		}
	}
	record, noOriginal, err := s.linkReceipt(entry)
	if err != nil {
		return err
	}
	if noOriginal && sealed {
		return errors.New("encrypted rollback conflicts with its receipt; client preserved")
	}
	if record && !noOriginal && !sealed {
		return errors.New("the encrypted rollback is missing; client preserved")
	}
	if action == "unlink" && sealed {
		if !record {
			return errors.New("encrypted rollback has no receipt; client and backup preserved")
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
			if noOriginal && !s.isLinked(entry) {
				return errors.New("client file replaced the managed link; file and receipt preserved")
			}
			if s.isLinked(entry) && !sealed {
				legacy, err := existsEntry(entry + configBackupSuffix)
				if err != nil {
					return err
				}
				switch {
				case legacy && noOriginal:
					return errors.New("legacy backup conflicts with the no-original receipt; client and backup preserved")
				case noOriginal:
					fmt.Fprintln(os.Stdout, "Already linked.")
					return nil
				case !legacy:
					return errors.New("original backup and receipt are both missing; locate the original or inspect the managed link before detaching it")
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
		// Re-read the receipt inside both client locks, including on retry after a crash.
		record, noOriginal, err := s.linkReceipt(entry)
		if err != nil {
			return err
		}
		if record && !noOriginal {
			return errors.New("rollback receipt requires the encrypted original; client preserved")
		}
		if action == "unlink" {
			if present, err := existsEntry(entry + sealedSuffix); err != nil || present {
				return errors.New("rollback changed; retry unlink")
			}
			return s.unlinkWithoutCipher(entry, noOriginal)
		}
		for _, suffix := range []string{"", configBackupSuffix, sealedSuffix} {
			if present, err := existsEntry(entry + suffix); err != nil || present {
				return errors.New("client file or rollback already exists")
			}
		}
		if !noOriginal {
			if err := publishNew(s.receipt(entry), []byte(noOriginalReceipt)); err != nil {
				return err
			}
		}
		if err := os.Symlink(filepath.Join(s.state, "current", "kubeconfig"), entry); err != nil {
			return err
		}
		return syncDir(filepath.Dir(entry))
	})
}

// Run under the alias and entry locks. A missing legacy backup alone never
// authorizes removal of a client link, even if it disappeared during restore.
func (s *service) unlinkWithoutCipher(entry string, noOriginal bool) error {
	legacy, err := existsEntry(entry + configBackupSuffix)
	if err != nil {
		return err
	}
	if !noOriginal {
		if !legacy {
			if !s.isLinked(entry) {
				return errors.New("client is not linked to this vault and has no rollback receipt or backup")
			}
			return errors.New("original backup and receipt are both missing; locate the original or inspect the managed link before detaching it")
		}
		if !s.isLinked(entry) {
			return errors.New("client file is not linked to this vault")
		}
		return restoreLegacyConfigLink(entry)
	}
	if legacy {
		return errors.New("legacy backup conflicts with the no-original receipt; client and backup preserved")
	}
	exists, err := existsEntry(entry)
	if err != nil {
		return err
	}
	if exists {
		if !s.isLinked(entry) {
			return errors.New("client file is not linked to this vault")
		}
		if err := os.Remove(entry); err != nil {
			return err
		}
	}
	// If removal finished before a crash, retry from here and clear the
	// receipt only after the missing client entry is durable.
	if err := syncDir(filepath.Dir(entry)); err != nil {
		return err
	}
	if err := os.Remove(s.receipt(entry)); err != nil {
		return err
	}
	if err := syncDir(s.state); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Detached %s. It had no original file.\n", entry)
	return nil
}
