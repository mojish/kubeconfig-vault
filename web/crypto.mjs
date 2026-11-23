// Browser WebCrypto only. PRF output and derived keys are never serialized.
const encoder = new TextEncoder();
const PURPOSE = encoder.encode("kube-unlock compatibility probe encryption v1");
const AAD = encoder.encode("kube-unlock dummy sample v1");

export function decode(value) {
  return Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
}

export function encode(value) {
  return btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function derive(prf, salt, purpose = PURPOSE) {
  const bytes = new Uint8Array(prf);
  if (bytes.byteLength !== 32) throw new Error("The authenticator did not return a valid PRF secret.");
  try {
    const material = await crypto.subtle.importKey("raw", bytes, "HKDF", false, ["deriveKey"]);
    return await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: decode(salt), info: purpose },
      material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
    );
  } finally {
    bytes.fill(0);
    new Uint8Array(prf).fill(0);
  }
}

export async function seal(prf, salt, sample, vault = false) {
  const key = await derive(prf, salt, vault ? encoder.encode("kube-unlock data key wrapping v1") : PURPOSE);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: AAD, tagLength: 128 }, key, decode(sample),
  );
  return { iv: encode(iv), ciphertext: encode(ciphertext) };
}

export async function open(prf, salt, envelope, vault = false) {
  const key = await derive(prf, salt, vault ? encoder.encode("kube-unlock data key wrapping v1") : PURPOSE);
  const sample = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: decode(envelope.iv), additionalData: AAD, tagLength: 128 },
    key, decode(envelope.ciphertext),
  );
  try {
    return encode(sample);
  } finally {
    new Uint8Array(sample).fill(0);
  }
}
