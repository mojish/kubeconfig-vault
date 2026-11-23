import { encode, decode, seal, open } from "./crypto.mjs";

const requestId = location.hash.slice(1);
history.replaceState(null, "", "/");
// A browser may reuse this tab for a later local unlock link.
window.addEventListener("hashchange", () => { if (location.hash) location.reload(); });
const button = document.querySelector("#continue");
const error = document.querySelector("#error");
const status = document.querySelector("#status");
const selector = document.querySelector("#key");

async function api(operation, body = {}) {
  const response = await fetch(`/api/${operation}`, {
    method: "POST", headers: { "Content-Type": "application/json", "X-Unlock-Request": requestId },
    body: JSON.stringify(body), cache: "no-store",
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Local request failed.");
  return result;
}

function options(raw) {
  const data = structuredClone(raw), key = data.publicKey;
  key.challenge = decode(key.challenge);
  if (key.user) key.user.id = decode(key.user.id);
  for (const list of [key.allowCredentials, key.excludeCredentials]) {
    for (const item of list || []) item.id = decode(item.id);
  }
  if (key.extensions?.prf?.eval) key.extensions.prf.eval.first = decode(key.extensions.prf.eval.first);
  return data;
}

function serialize(credential) {
  const response = { clientDataJSON: encode(credential.response.clientDataJSON) };
  for (const name of ["attestationObject", "authenticatorData", "signature", "userHandle"]) {
    if (credential.response[name]) response[name] = encode(credential.response[name]);
  }
  return { id: credential.id, rawId: encode(credential.rawId), type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment, response };
}

async function refresh() {
  const state = await api("status");
  document.body.dataset.stage = state.mode;
  selector.replaceChildren();
  for (const key of state.keys) {
    const item = document.createElement("option");
    item.value = key.index;
    item.textContent = key.name;
    selector.append(item);
  }
  selector.hidden = state.keys.length <= 1;
  button.textContent = state.mode === "enroll"
    ? state.registered ? "Protect vault with this key" : "Register security key"
    : "Unlock configuration";
  status.textContent = state.mode === "enroll"
    ? "Register the USB YubiKey you want to use. Your existing SSH keys are unchanged."
    : "Use your registered USB YubiKey. The waiting command will continue after you unlock.";
  button.disabled = false;
}

button.addEventListener("click", async () => {
  button.disabled = true;
  error.textContent = "";
  try {
    const step = await api("begin", { key: Number(selector.value || 0) });
    const credential = step.registering
      ? await navigator.credentials.create(options(step.options))
      : await navigator.credentials.get(options(step.options));
    if (!credential) throw new Error("No security key was selected.");
    const payload = { request: step.request, credential: serialize(credential) };
    const extension = credential.getClientExtensionResults().prf;
    if (step.registering) {
      if (!extension?.enabled) throw new Error("This browser/key does not support the required encryption feature.");
      payload.prfEnabled = true;
    } else {
      const prf = extension?.results?.first;
      if (!prf) throw new Error("The security key did not return an encryption secret.");
      if (step.mode === "enroll") {
        const key = step.dataKey ? decode(step.dataKey) : crypto.getRandomValues(new Uint8Array(32));
        try {
          payload.envelope = await seal(prf, step.kdfSalt, encode(key), true);
          payload.dataKey = encode(key);
        } finally { key.fill(0); }
      } else {
        payload.dataKey = await open(prf, step.kdfSalt, step.envelope, true);
      }
    }
    const result = await api("finish", payload);
    delete payload.dataKey;
    if (result.registered) await refresh();
    else {
      document.body.dataset.stage = "passed";
      status.textContent = "Unlocked. Your waiting command can continue. You may close this page.";
      button.textContent = "Unlocked";
      document.querySelector("#cancel").disabled = true;
    }
  } catch (err) {
    error.textContent = err.name === "NotAllowedError" ? "Cancelled or timed out. Retry or cancel the unlock."
      : err.name === "OperationError" ? "This key could not decrypt the vault." : err.message;
    button.disabled = false;
  }
});

document.querySelector("#cancel").addEventListener("click", async () => {
  try { await api("cancel"); } catch {}
  status.textContent = "Cancelled. You may close this page.";
  button.disabled = true;
  document.querySelector("#cancel").disabled = true;
});

refresh().catch(err => { error.textContent = err.message; });
