import { decode, encode, seal, open } from "./crypto.mjs";

const status = document.querySelector("#status");
const button = document.querySelector("#continue");
const error = document.querySelector("#error");
const steps = {
  new: ["register", "1. Register test key", "Select your USB security key. Use the browser's PIN prompt and touch the key when asked."],
  registered: ["seal", "2. Encrypt dummy message", "The next touch creates an encryption key for a random dummy message. The page then reloads to discard that key."],
  sealed: ["open", "3. Unlock dummy message", "The previous encryption key was discarded. Use the same YubiKey to recover it and decrypt the message."],
  passed: [null, "Compatibility test passed", "Your browser and selected key successfully encrypted and recovered the dummy message. No Kubernetes configuration was accessed."],
};
let session;

async function api(path, body) {
  const response = await fetch(path, body === undefined ? { cache: "no-store" } : {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Probe-CSRF": session.csrf },
    body: JSON.stringify(body),
    cache: "no-store",
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "The local request failed.");
  return result;
}

function options(raw) {
  const result = structuredClone(raw);
  const key = result.publicKey;
  key.challenge = decode(key.challenge);
  if (key.user) key.user.id = decode(key.user.id);
  for (const credential of key.allowCredentials || []) credential.id = decode(credential.id);
  if (key.extensions?.prf?.eval) key.extensions.prf.eval.first = decode(key.extensions.prf.eval.first);
  return result;
}

function serialize(credential) {
  // Deliberately do not call credential.toJSON(): extension results may contain PRF secrets.
  const response = { clientDataJSON: encode(credential.response.clientDataJSON) };
  for (const name of ["attestationObject", "authenticatorData", "signature", "userHandle"]) {
    if (credential.response[name]) response[name] = encode(credential.response[name]);
  }
  return {
    id: credential.id, rawId: encode(credential.rawId), type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment, response,
  };
}

async function refresh() {
  session = await api("/api/status");
  const [action, label, description] = steps[session.stage];
  document.querySelector("#stage").textContent = label;
  status.textContent = description;
  button.textContent = label;
  button.disabled = !action;
  document.body.dataset.stage = session.stage;
}

button.addEventListener("click", async () => {
  error.textContent = "";
  button.disabled = true;
  try {
    const [action] = steps[session.stage];
    const request = await api("/api/begin", { action });
    const credential = action === "register"
      ? await navigator.credentials.create(options(request.options))
      : await navigator.credentials.get(options(request.options));
    if (!credential) throw new Error("No security key was selected.");
    const result = { action, request: request.request, credential: serialize(credential) };
    const extension = credential.getClientExtensionResults().prf;
    if (action === "register") {
      if (!extension?.enabled) throw new Error("PRF is unavailable with this browser and key. Try an up-to-date Chrome with your USB YubiKey.");
      result.prfEnabled = true;
    } else {
      const secret = extension?.results?.first;
      if (!secret) throw new Error("The browser did not return a PRF secret. This combination cannot unlock the encrypted configuration.");
      if (action === "seal") result.envelope = await seal(secret, request.kdfSalt, request.sample);
      else result.sample = await open(secret, request.kdfSalt, request.envelope);
    }
    await api("/api/finish", result);
    if (action === "seal") {
      // A new document has no reference to the PRF output or CryptoKey from sealing.
      location.reload();
      return;
    }
    await refresh();
  } catch (err) {
    error.textContent = err.name === "NotAllowedError"
      ? "The key request was cancelled or timed out. You can retry this step."
      : err.name === "OperationError"
        ? "The key could not decrypt the sample. Compatibility has not been established."
        : err.message || "The compatibility test failed.";
    button.disabled = false;
  }
});

if (!window.isSecureContext || !window.PublicKeyCredential || !window.crypto?.subtle) {
  error.textContent = "This browser cannot run the test. Open the printed localhost address in a browser with WebAuthn support.";
} else {
  refresh().catch(err => { error.textContent = err.message; });
}
