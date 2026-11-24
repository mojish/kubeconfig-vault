package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

func (s *service) editConfig() error {
	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		editor = "vi"
	}
	// Prefer a literal executable path, including paths with spaces. Arguments
	// are whitespace-delimited and are never interpreted by a shell.
	argv := []string{editor}
	if _, err := exec.LookPath(editor); err != nil {
		argv = strings.Fields(editor)
	}
	if len(argv) == 0 {
		return errors.New("set VISUAL or EDITOR to an editor executable")
	}
	binary, err := exec.LookPath(argv[0])
	if err != nil {
		return errors.New("cannot find editor; set VISUAL or EDITOR")
	}
	switch filepath.Base(binary) {
	case "code", "code-insiders", "codium", "cursor", "subl":
		if !slices.Contains(argv, "--wait") && !slices.Contains(argv, "-w") {
			argv = append(argv, "--wait")
		}
	}
	result, err := s.rpc(request{Op: "config-unlock"})
	if err != nil {
		return err
	}
	var status struct {
		EditPath string `json:"edit_path"`
	}
	if err := json.Unmarshal(result, &status); err != nil || status.EditPath != s.editPath() {
		return errors.New("cannot locate private edit")
	}
	cmd := exec.Command(binary, append(argv[1:], status.EditPath)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return errors.New("editor exited unsuccessfully; run kubeconfig-vault path edit to locate your preserved plaintext edit, then save and close your editor and run kubeconfig-vault config lock")
	}
	if result, err = s.rpc(request{Op: "config-lock"}); err != nil {
		return err
	}
	var saved struct {
		Changed *bool `json:"changed"`
	}
	if err = json.Unmarshal(result, &saved); err != nil {
		return err
	}
	if saved.Changed != nil && !*saved.Changed {
		fmt.Fprintln(os.Stdout, "No changes.")
	} else {
		fmt.Fprintln(os.Stdout, "Changes encrypted and verified.")
	}
	return nil
}
