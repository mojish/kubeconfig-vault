package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMigrateCommandRequiresInstallerAlias(t *testing.T) {
	for _, tc := range []struct {
		name, link string
		migrate    bool
	}{
		{"absent", "", false},
		{"other target", "custom-helper", false},
		{"installer link", commandName, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			legacy := filepath.Join(dir, legacyCommandName)
			current := filepath.Join(dir, commandName)
			if tc.link != "" {
				if err := os.Symlink(tc.link, legacy); err != nil {
					t.Fatal(err)
				}
			}
			other := filepath.Join(dir, "other-bin", legacyCommandName)
			approved := config{Users: []namedUser{
				{User: auth{Exec: &execConfig{Command: legacy}}},
				{User: auth{Exec: &execConfig{Command: other}}},
			}}
			want := legacy
			if tc.migrate {
				want = current
			}
			migrateCommandName(&approved, current)
			if got := approved.Users[0].User.Exec.Command; got != want {
				t.Errorf("migrated command = %q, want %q", got, want)
			}
			if got := approved.Users[1].User.Exec.Command; got != other {
				t.Errorf("unrelated command changed to %q", got)
			}
		})
	}
}
