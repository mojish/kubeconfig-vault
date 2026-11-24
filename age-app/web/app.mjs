import { Stanza, webauthn } from "age-encryption";

let capability = location.hash.slice(1);
history.replaceState(null, "", "/");
const button = document.querySelector("#continue"), message = document.querySelector("#message"), progress = document.querySelector("#progress");
const decline = document.querySelector("#decline");
const encode = bytes => btoa(String.fromCharCode(...bytes));
const decode = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
let active = null, busy = false, finished = false, polling = false, revision = 0;
let enrolled = false, timer;
function finish(text, displayed = false) {
  clearInterval(timer);
  finished = true; revision++; active = null;
  decline.disabled = button.disabled = true; button.textContent = "Session closed"; message.textContent = text;
  if (displayed) void api("/api/poll", {displayed:true}).catch(() => {});
  capability = "";
}
async function api(path, value) {
  const response = await fetch(path, { method: "POST", credentials: "omit", cache: "no-store",
    signal: AbortSignal.timeout(15000),
    headers: { "Content-Type": "application/json", "X-Unlock-Capability": capability }, body: JSON.stringify(value) });
  if (!response.ok) throw new Error("Local request rejected");
  return await response.json();
}
async function poll() {
  if (busy || finished || polling) return;
  polling = true;
  const expected = revision;
  try {
    const page = await api("/api/poll", {});
    // A request started before a click/failure must not restore the old step.
    if (busy || finished || expected !== revision) return;
    const title = document.querySelector("#title");
    if (title.textContent !== page.title) title.textContent = page.title;
    if (page.done) {
      const success = enrolled
        ? "Vault verified. Its non-discoverable credential normally stays hidden in Yubico Authenticator’s Passkeys list. You can close this page."
        : "Finished. You can close this page and return to your application.";
      finish(page.success ? success : "Operation failed. Check the terminal for the result.", true);
      button.textContent = page.success ? "Completed" : "Operation failed";
    } else if (page.request) {
      if (active?.id === page.request.id) return;
      active = page.request; decline.disabled = button.disabled = false;
      progress.textContent = `Step ${active.step} of ${active.total}`;
      button.textContent = ({enroll:"Set up security key",wrap:"Protect the vault",unwrap:active.total > 1 && active.step === active.total ? "Verify the encrypted vault" : "Unlock with security key"})[active.op];
      message.textContent = ({enroll:"Create a credential on your YubiKey.",wrap:"Protect this new vault generation with your YubiKey.",unwrap:"Authenticate with your YubiKey to decrypt and verify this vault."})[active.op];
    } else {
      active = null; decline.disabled = button.disabled = true; button.textContent = "Checking…";
      if (message.textContent !== "Waiting for the local application…") message.textContent = "Waiting for the local application…";
    }
  } catch {
    if (!busy && !finished && expected === revision) finish("This page can no longer reach the vault. Check the result in your terminal or Kubernetes app before starting again.");
  } finally { polling = false; }
}
decline.addEventListener("click", async () => {
  if (busy || finished || !active) return;
  busy = true; revision++; decline.disabled = button.disabled = true;
  const id = active.id;
  active.fileKey = ""; active = null;
  try {
    await api("/api/reply", {id, declined:true});
    finish("Request declined. You can close this page.");
  } catch {
    finish("The local helper did not confirm the decline. You can close this page.");
  }
});
button.addEventListener("click", async () => {
  if (busy || finished || !active) return;
  busy = true; revision++; decline.disabled = button.disabled = true; button.textContent = "Waiting for security key…";
  message.textContent = "Complete your browser’s security-key prompt. This step stays disabled while the browser is waiting.";
  const request = active; active = null;
  let reply = { id: request.id }, key, authFailed = false;
  try {
    if (request.op === "enroll") {
      reply.identity = await webauthn.createCredential({ type: "security-key", keyName: "Kubeconfig Vault", rpId: "localhost" });
      enrolled = true;
    } else if (request.op === "wrap") {
      key = decode(request.fileKey); request.fileKey = "";
      reply.stanzas = (await new webauthn.WebAuthnRecipient({ identity: request.identity }).wrapFileKey(key)).map(s => ({ type:s.args[0], args:s.args.slice(1), body:encode(s.body) }));
    } else if (request.op === "unwrap") {
      key = await new webauthn.WebAuthnIdentity({ identity: request.identity }).unwrapFileKey(request.stanzas.map(s => new Stanza([s.type,...s.args],decode(s.body))));
      if (!key) throw new Error("No matching key");
      reply.fileKey = encode(key);
    } else throw new Error("Unsupported operation");
  } catch { authFailed = true; reply = {id:request.id, failed:true}; }
  finally { key?.fill(0); request.fileKey = ""; }
  message.textContent = authFailed ? "Security-key authentication failed or was cancelled. Notifying the local application…" : "Security-key response received. Checking it with the local application…";
  button.textContent = "Checking…";
  try {
    await api("/api/reply", reply);
    if (authFailed) finish("Security-key authentication failed or was cancelled. Start a new operation from your application.");
  } catch { finish("Local application rejected the response or stopped responding. Check the terminal and start a new operation."); }
  finally { reply.fileKey = ""; busy = false; }
  await poll();
});
if (!/^[a-f0-9]{64}$/.test(capability)) finish("Start an operation from kubeconfig-vault to open a new authentication page.");
else { await poll(); if (!finished) timer = setInterval(poll, 300); }
