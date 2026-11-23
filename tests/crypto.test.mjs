import { test } from "node:test";
import assert from "node:assert/strict";
import { seal, open, encode, decode } from "../web/crypto.mjs";

const random = size => crypto.getRandomValues(new Uint8Array(size));

test("a freshly derived key decrypts the original sample", async () => {
  const secret = random(32), salt = encode(random(32)), sample = encode(random(48));
  const input = secret.slice().buffer;
  const envelope = await seal(input, salt, sample);
  assert.deepEqual(new Uint8Array(input), new Uint8Array(32));
  assert.equal(await open(secret.slice().buffer, salt, envelope), sample);
});

test("different PRF output and salt both fail to decrypt", async () => {
  const secret = random(32), salt = encode(random(32));
  const envelope = await seal(secret.slice().buffer, salt, encode(random(48)));
  await assert.rejects(open(random(32).buffer, salt, envelope));
  await assert.rejects(open(secret.slice().buffer, encode(random(32)), envelope));
});

test("tampering with ciphertext or nonce fails authentication", async () => {
  const secret = random(32), salt = encode(random(32));
  const envelope = await seal(secret.slice().buffer, salt, encode(random(48)));
  for (const name of ["iv", "ciphertext"]) {
    const altered = decode(envelope[name]);
    altered[0] ^= 1;
    await assert.rejects(open(secret.slice().buffer, salt, { ...envelope, [name]: encode(altered) }));
  }
});

test("each encryption uses a fresh nonce", async () => {
  const secret = random(32), salt = encode(random(32)), sample = encode(random(48));
  const a = await seal(secret.slice().buffer, salt, sample);
  const b = await seal(secret.slice().buffer, salt, sample);
  assert.notEqual(a.iv, b.iv);
  assert.notEqual(a.ciphertext, b.ciphertext);
});

test("missing or malformed PRF output cannot become a key", async () => {
  for (const length of [0, 16, 31, 33]) {
    await assert.rejects(seal(random(length).buffer, encode(random(32)), encode(random(48))));
  }
});

test("probe encryption and vault wrapping use distinct derived keys", async () => {
  const secret = random(32), salt = encode(random(32)), key = encode(random(32));
  const envelope = await seal(secret.slice().buffer, salt, key, true);
  assert.equal(await open(secret.slice().buffer, salt, envelope, true), key);
  await assert.rejects(open(secret.slice().buffer, salt, envelope));
});
