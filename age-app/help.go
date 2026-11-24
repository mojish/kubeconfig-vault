package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

const overview = `Kubeconfig Vault · experimental

Get started
  kubeconfig-vault setup       Protect your kubeconfig with a security key.
                               Then use kubectl or Freelens as usual.

Everyday commands
  status                       Check the session and any open plaintext edit.
  edit                         Change your kubeconfig in your normal editor.
  lock                         End the current session.
  unlock                       Approve access now.

Backup and recovery
  backup FILE.age              Save an encrypted copy.
  help recovery                Restore a backup or check your offline key.

Use "kubeconfig-vault help COMMAND" for examples.
More topics: config, advanced, options.`

const configHelp = `Manage the linked kubeconfig

  edit                                    Open your editor, then save and verify.
  config unlock                           Create a plaintext file for editing.
  path edit                               Show the file to open in your editor.
  config lock [--accept-connection-changes]  Save the edit after closing the editor.
  config discard                          Delete unsaved edits.
  config link [--kubeconfig FILE]         Attach a client path to the vault.
  config unlink [--kubeconfig FILE]       Restore the original pre-setup file.
  config repair [--kubeconfig FILE]       Rebuild a missing generated client file.

For a walkthrough, run kubeconfig-vault help edit.`

const recoveryHelp = `Choose the recovery operation you need

  backup NEW-FILE                         Save the current encrypted vault.
  recover VAULT.age --check               Check a backup and your offline key.
  restore VAULT.age                       Enroll a security key on a new laptop.
  recover VAULT.age --out NEW-FILE        Write a portable plaintext kubeconfig.
  export NEW-FILE                         Export plaintext with your security key.

For example, run kubeconfig-vault recover cluster-backup.age --check.
Paste your offline key at the hidden prompt, or add --key FILE after the
backup name. For recover, --key can go before or after --check or --out.`

const advancedHelp = `Advanced commands

  import [SOURCE]                         Create a vault and keep the source file.
  import SOURCE --recovery-key FILE       Import using an existing offline key.
  recovery-key new FILE                   Generate a private offline key file.
  recovery-key public FILE                Print only its public recipient.
  history prune --keep COUNT              Retain the active and newest generations.
  path kubeconfig|edit|vault              Locate an existing vault file.
  stop                                    Clear the session and exit the helper.
  serve                                   Run the helper in the foreground.
  credential ID                           Kubernetes exec plugin entry point.

See also: kubeconfig-vault help config, help recovery, and help options.`

func printHelp(w io.Writer, topic []string) error {
	var message string
	switch strings.Join(topic, " ") {
	case "", "help", "--help", "-h":
		message = overview
	case "setup":
		message = `kubeconfig-vault setup [FILE]
kubeconfig-vault setup --check [FILE]

Close your kubeconfig editor, connect your security key, then run:
  kubeconfig-vault setup

Save the generated offline recovery key and complete the local browser steps.
Setup selects ~/.kube/config or the single file named by KUBECONFIG.
To validate a file without enrollment, run kubeconfig-vault setup --check FILE.
If you already have a hybrid age key from kubeconfig-vault recovery-key new FILE,
add --recovery-key FILE during setup. Browser approval is still required.`
	case "edit", "config edit":
		message = `kubeconfig-vault edit

Approve with your security key, edit the file, then save and close your editor.
The helper verifies and encrypts your changes. An unsuccessful save preserves
the plaintext edit. Run kubeconfig-vault status to locate it.

To edit in separate steps, see kubeconfig-vault help config.`
	case "status":
		message = `kubeconfig-vault status [--json]

Show the session deadline, any open edit, and what to do if the vault needs
attention. Status can run before setup or while the helper is stopped.`
	case "lock":
		message = `kubeconfig-vault lock [--json]

End the helper's credential session. An open plaintext edit stays on disk.
To finish editing, save and close your editor and run kubeconfig-vault config lock.
Clients are asked to refresh within 60 seconds. The API server controls
credential validity, and established connections can stay open.`
	case "unlock":
		message = `kubeconfig-vault unlock

Approve a credential session in the browser. Use this command to resume
access immediately after declining an unexpected automatic request.`
	case "stop":
		message = `kubeconfig-vault stop [--json]

End the credential session and shut down the helper. A plaintext edit stays
on disk. The next command that needs the helper can start it again.`
	case "config":
		message = configHelp
	case "config unlock":
		message = `kubeconfig-vault config unlock

Approve with your security key to open a private plaintext copy for editing.
Run kubeconfig-vault path edit to find it. After saving and closing your
editor, run kubeconfig-vault config lock to encrypt and verify your changes.`
	case "config lock":
		message = `kubeconfig-vault config lock [--accept-connection-changes]

Save and close your editor first. This command validates the edit, verifies
the encrypted save, and removes the plaintext working copy. If you changed
a server address, TLS trust, or user mapping, review those changes before
adding --accept-connection-changes.`
	case "config discard":
		message = `kubeconfig-vault config discard

Delete unsaved plaintext editing files and clear the session. The last
encrypted save stays available. Run kubeconfig-vault status first if a save
was interrupted, and preserve any changes you need from each listed file.`
	case "config link":
		message = `kubeconfig-vault config link [--kubeconfig FILE]

Attach a client path to an existing vault. Choose the path kubectl or
Freelens reads. For first-time protection, use kubeconfig-vault setup.`
	case "config unlink":
		message = `kubeconfig-vault config unlink [--kubeconfig FILE]

Undo setup for this client path. Close your editor and quit clients first.
Make a backup or export any changes you saved after setup. Approve with
your key to restore the original plaintext file. If the path was originally
empty, the managed link is removed.`
	case "config repair":
		message = `kubeconfig-vault config repair [--kubeconfig FILE]

If status reports a missing generated client file, approve with your
security key to rebuild it from the last encrypted save. You may need to
select your context or namespace again afterward.`
	case "recovery":
		message = recoveryHelp
	case "backup":
		message = `kubeconfig-vault backup NEW-FILE

Copy the latest encrypted kubeconfig to a new file. Save any edits you want
to include before making the backup.
Keep the backup and your offline recovery key in separate safe places.

To make and check a backup, run
  kubeconfig-vault backup cluster-backup.age
  kubeconfig-vault recover cluster-backup.age --check`
	case "recover":
		message = `kubeconfig-vault recover VAULT.age --check
kubeconfig-vault recover VAULT.age --out NEW-FILE

Use --check to verify that your offline key decrypts a trusted backup.
Use --out to write a new plaintext kubeconfig containing usable credentials.
Enter your offline key at the hidden prompt, or pass --key FILE.

To check a backup, run
  kubeconfig-vault recover cluster-backup.age --check`
	case "restore":
		message = `kubeconfig-vault restore VAULT.age [--key FILE]

Set up a new vault from a trusted encrypted backup. Use an unused vault
directory, your offline recovery key, and the security key you want to enroll.
Enter the offline key at the hidden prompt, or pass its file with --key.

On a new laptop, run
  kubeconfig-vault restore cluster-backup.age
  kubeconfig-vault config link

If this laptop already has a vault, put --state-dir NEW-DIR before each
command and --kubeconfig NEW-FILE after config link.`
	case "export":
		message = `kubeconfig-vault export NEW-FILE

Write the latest saved kubeconfig as plaintext. Approve with your enrolled
security key and choose a new filename. The file contains usable credentials.

For a file you can use with kubectl, run
  kubeconfig-vault export recovered-config`
	case "advanced", "import", "path", "serve", "credential", "recovery-key", "recovery-key new", "recovery-key public", "history", "history prune":
		message = advancedHelp
	case "options":
		message = `kubeconfig-vault [global options] COMMAND

  --version             Print the installed version.
  --state-dir PATH      Use a private vault directory at PATH.
  --browser PATH        Open approval pages with this launcher executable.
  --session-seconds N   Set the session lifetime for a new helper (1–3600).

Example: kubeconfig-vault --session-seconds 900 unlock
Stop an existing helper before changing its session or browser settings.`
	default:
		return errors.New("unknown help topic; run kubeconfig-vault help")
	}
	_, err := fmt.Fprintln(w, message)
	return err
}
