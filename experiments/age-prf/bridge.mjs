// Synthetic experiment only. This module is not loaded by the installed helper.
import { Stanza, webauthn } from "age-encryption";

const encode = bytes => btoa(String.fromCharCode(...bytes));
const decode = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
const toWire = stanza => ({ type: stanza.args[0], args: stanza.args.slice(1), body: encode(stanza.body) });
const fromWire = stanza => new Stanza([stanza.type, ...stanza.args], decode(stanza.body));

// The bridge sees file keys and recipient stanzas, never the native payload.
// The test harness keeps identity metadata outside the page across reloads.
window.ageExperiment = {
  async enroll() {
    return await webauthn.createCredential({ type: "security-key", keyName: "Synthetic age compatibility test", rpId: "localhost" });
  },
  async wrap(identity, fileKey) {
    const key = decode(fileKey);
    try {
      return (await new webauthn.WebAuthnRecipient({ identity }).wrapFileKey(key)).map(toWire);
    } finally {
      key.fill(0);
    }
  },
  async unwrap(identity, stanzas) {
    const key = await new webauthn.WebAuthnIdentity({ identity }).unwrapFileKey(stanzas.map(fromWire));
    if (key === null) throw new Error("No matching key.");
    try { return encode(key); } finally { key.fill(0); }
  },
};
