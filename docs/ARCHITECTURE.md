# Architecture and security boundaries

The vault and credential helper run on the user’s laptop. Kubernetes validates
the existing bearer token.

## Encryption and unlock

Go age v1.3.2 encrypts the complete payload; Typage v0.3.1 implements WebAuthn PRF
recipient operations. Browser assets are bundled and embedded in the binary.

Every generation uses a fresh age file key with two recipients: a WebAuthn PRF
credential and a hybrid age offline recovery recipient. Only the recovery public
recipient persists in state. Interactive import displays the private identity
through the controlling terminal after an explicit reveal. After backup
confirmation the CLI passes it over the private, peer-checked Unix socket for
verification. It does not write it to a file, standard output, or the browser.
The optional `recovery-key new` command creates a private file with mode 0600.
Keep the identity separately because it can decrypt without the YubiKey.
Back up the entire state directory,
including Typage's nonsecret identity string needed to select a non-discoverable
credential, as well as the independent recovery key.

The browser sees age file keys and recipient stanzas, never Kubernetes plaintext
or the private recovery key. PRF derivation stays in Typage/browser memory.
Native age authenticates the complete header and payload before accepting an
unlock. There is no backend assertion-signature login or trusted authentication
boolean: successful authenticated decryption is the proof. Typage requires user
verification and requests a security key, but does not attest the manufacturer
or exclude compatible software credential providers.

The browser and helper communicate over loopback HTTP. Each operation gets an
IPv4 loopback listener, a random localhost
port, a 256-bit fragment capability, exact Host/Origin checks, a dedicated request
header, bounded JSON, and single-use step IDs. CSP blocks external assets and
framing; responses are not cached, the fragment is cleared, and browser storage
is unused. Operations time out after five minutes. Lock or client disconnect
cancels pending authentication. The localhost RP is not application-exclusive:
WebAuthn does not scope it by port. Same-user process/browser compromise remains
outside this protection.

The launcher receives a `file:` URI for a mode-0600 HTML redirect in a private
mode-0700 temporary directory. The capability is inside that file, not process
arguments or desktop launch arguments. The browser follows the redirect to the
loopback page. Only cross-site top-level document navigation to `/` is allowed
for this handoff. Cross-site API calls and subresources remain rejected, even
with a capability. The bootstrap is removed after the first authenticated API
request, launch failure, or cancellation. A forced process crash can leave a
private bootstrap file containing an expired capability. It contains no file key.

Each browser step displays its number and purpose. Only one status poll runs at
a time. Responses from before a click or terminal failure cannot restore an old
step or re-enable its button. The page distinguishes waiting for the browser's
security-key prompt from waiting for native verification, and bounds each local
HTTP request to 15 seconds. A browser failure remains visible until a new
operation is started.

Private Unix IPC checks peer UID on Linux and macOS. Management operations are
serialized, and successful concurrent cold requests reuse one unlock. The
default one-hour session retains token records, approved public settings, and
generation ID, not the full source or age file keys. Retrieval does not extend
it. Both monotonic and wall-clock deadlines are checked; ordinary sleep does not
extend the wall deadline. Recognized JWT expiry can shorten delivery. Screen-lock
hooks are not implemented. Go/JavaScript cannot promise complete memory erasure.
Core dumps are disabled; swap and hibernation remain OS concerns.

After a failed automatic unlock, a 30-second cooldown prevents queued clients
from repeatedly opening browser tabs. Explicit `unlock` can retry immediately.

Import encrypts and decrypt-verifies the candidate with both YubiKey and recovery
identity before committing. Save authenticates the old vault, encrypts a fresh
candidate using its approved recipients, and decrypt-verifies through the YubiKey
before committing. This can require three security-key actions per save: decrypt
old, wrap new, verify new. Recovery private material is needed at import, not
ordinary saves; later recovery stanzas use the authenticated public recipient.

Generations hold `vault.age`, `metadata.json`, and token-free `kubeconfig`. Files
are checked against reader limits, written, and read back through the normal
generation loader before atomic `current` symlink replacement. This detects
invalid metadata and oversized generated configs before publishing the candidate.
Files are synced before replacement. All encrypted generations
are retained; no pruning/restore CLI exists yet. Failed staging can leave an
unreferenced encrypted generation. Sync failure after replacement explicitly
reports uncertain durability. Offline recovery needs only a standalone age
ciphertext and private recovery identity, without public metadata or a daemon.

## Editing and limitations

`config unlock` requires fresh authentication even with a cached session and
writes exact source text to `STATE/edit/kubeconfig`, mode 0600. **This is plaintext
on the state filesystem, not guaranteed RAM storage. It can survive logout,
reboot, a crash, or ordinary lock.** Status exposes the edit and reports
`fully_locked: false`. Save checks its generation, validates edits, preserves
client selections where source selections were unchanged, and requires explicit
acceptance of connection/trust/mapping changes. Validation failure retains the
old vault and edit. Successful commit clears the session before deleting the
edit; deletion failure is reported. Discard deletes the edit and clears cache.

After authentication, save renames the editable file to `STATE/edit/saving` and
compares it with the text used to encrypt the candidate. A change aborts commit
and preserves the plaintext. After commit, it checks the isolated file again
before cleanup. A new file created at the original edit path is never deleted
by save. Failure restores the isolated file only if the original path is absent.
Otherwise both remain visible in `status.edit_paths` and block a new edit/save.
An interrupted save can also leave the isolated file. Explicit discard removes
both known paths. These safeguards do not synchronize arbitrary processes that
retain writable descriptors: **close the editor before locking**. A write through
such a descriptor after the final check can still race cleanup.

Export requires fresh authentication. Export and offline recovery create portable
plaintext configs with embedded public CA data; formatting/comments are not
retained in these outputs. Ordinary editing preserves source text. Originals,
recovery files, exports, editor artifacts, snapshots, and unsaved edits require
separate protection. Deletion is not secure erasure on SSDs/snapshot filesystems.

The input contract supports inline bearer tokens, verified HTTPS, public
CA data/files, and standard named contexts. Legacy preferences stay in the
encrypted source. Token files, client certificates, exec/auth-provider sources,
extensions outside preferences, and unknown fields are rejected. No token is
rotated. Client-go/Freelens can retain delivered tokens
and existing streams after lock. Linux tests cover real kubectl, the Freelens
Kubernetes proxy, and the Freelens 2.1.0 GUI with synthetic data. CI runs native
tests on Apple Silicon and Intel macOS. Desktop browser and physical-key testing
on macOS are pending.
A physical USB YubiKey passed the [Linux hardware test](DEVELOPMENT.md#test-with-a-physical-yubikey).
Typage’s WebAuthn API is experimental. The application has not had an independent
security review.

CA inputs must contain only valid public certificate PEM blocks and surrounding
whitespace. Unexpected text, PEM headers, private keys, and malformed blocks are
rejected. The public projection embeds re-encoded certificates only. This avoids
copying unrelated contents of a mixed PEM file into the unencrypted projection.

`config link` backs up the existing client entry and atomically points its path
at the generated kubeconfig. It uses the client-go lock file convention to
avoid races with `kubectl config` writes. Vault saves replace the `current`
generation link without changing the client path. The original backup may still
contain plaintext credentials and needs separate protection.
