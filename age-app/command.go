package main

import (
	"os"
	"path/filepath"
)

const commandName = "kubeconfig-vault"
const legacyCommandName = "kube-unlock-age"

// os.Executable can return either the invoked link or its target, depending on the OS.
func installedCommand(path string) string {
	if filepath.Base(path) == legacyCommandName {
		if target, err := os.Readlink(path); err == nil && target == commandName {
			return filepath.Join(filepath.Dir(path), commandName)
		}
	}
	return path
}

// Only translate the installer-created alias in an already authenticated projection.
// All other changes to an exec command still go through the ordinary settings check.
func migrateCommandName(approved *config, executable string) {
	if filepath.Base(executable) != commandName {
		return
	}
	legacy := filepath.Join(filepath.Dir(executable), legacyCommandName)
	if installedCommand(legacy) != executable {
		return
	}
	for _, user := range approved.Users {
		if exec := user.User.Exec; exec != nil && exec.Command == legacy {
			exec.Command = executable
		}
	}
}
