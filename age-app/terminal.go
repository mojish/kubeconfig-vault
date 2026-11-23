package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"filippo.io/age"
	"golang.org/x/term"
)

func recoveryTerminal(fileOption string) (*os.File, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err == nil && term.IsTerminal(int(tty.Fd())) {
		return tty, nil
	}
	if tty != nil {
		_ = tty.Close()
	}
	return nil, fmt.Errorf("a terminal is required; use %s FILE for unattended use", fileOption)
}

func showNewRecoveryKey() ([]byte, error) {
	tty, err := recoveryTerminal("--recovery-key")
	if err != nil {
		return nil, err
	}
	defer tty.Close()
	reader := bufio.NewReader(tty)
	if _, err = fmt.Fprint(tty, "Your recovery key can unlock the vault without your YubiKey.\nSave it separately in a password manager or on an encrypted drive.\nPress Enter to show it, or Ctrl+C to cancel. "); err != nil {
		return nil, err
	}
	if _, err = reader.ReadString('\n'); err != nil {
		return nil, errors.New("recovery key display cancelled")
	}
	identity, err := age.GenerateHybridIdentity()
	if err != nil {
		return nil, errors.New("cannot generate recovery key")
	}
	key := []byte(identity.String())
	if _, err = fmt.Fprintf(tty, "\n%s\n\nType saved to confirm you have a copy, then press Enter. ", key); err != nil {
		clear(key)
		return nil, err
	}
	reply, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(reply) != "saved" {
		clear(key)
		return nil, errors.New("import cancelled before vault creation")
	}
	return key, nil
}

func recoverFromTerminal(cipherPath, out string) error {
	key, err := promptRecoveryKey()
	if err != nil {
		return err
	}
	return recoverWithKey(cipherPath, out, key)
}

func promptRecoveryKey() (*age.HybridIdentity, error) {
	tty, err := recoveryTerminal("--key")
	if err != nil {
		return nil, err
	}
	defer tty.Close()
	secret, err := readHiddenRecoveryKey(tty)
	if err != nil && !errors.Is(err, term.ErrPasteIndicator) {
		return nil, errors.New("cannot read recovery key from the terminal")
	}
	return parseRecovery([]byte(secret))
}

func readHiddenRecoveryKey(tty *os.File) (string, error) {
	fd := int(tty.Fd())
	previous, err := term.MakeRaw(fd)
	if err != nil {
		return "", err
	}
	defer term.Restore(fd, previous)
	return term.NewTerminal(tty, "").ReadPassword("Paste your recovery key and press Enter (input is hidden): ")
}
