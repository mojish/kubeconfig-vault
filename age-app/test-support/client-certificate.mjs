// Generate a disposable client identity and require the exact leaf at the loopback server.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export async function clientCertificateFixture(directory) {
  const generator = fileURLToPath(new URL("./clientpki.go", import.meta.url));
  const generated = spawnSync("go", ["run", generator, directory], {
    env: { ...process.env, GO111MODULE: "off", GOTOOLCHAIN: "local" },
    stdio: "ignore", timeout: 90000,
  });
  assert.equal(generated.status, 0, "could not generate disposable client certificate");
  const issuer = join(directory, "issuer.crt");
  const leaf = join(directory, "client.crt");
  const verified = spawnSync("openssl", ["verify", "-purpose", "sslclient", "-CAfile", issuer, leaf],
    { stdio: "ignore", timeout: 15000 });
  assert.equal(verified.status, 0, "disposable client certificate failed verification");
  const [ca, clientCert, clientKey] = await Promise.all([issuer, leaf, join(directory, "client.key")].map(path => readFile(path)));
  const expected = new X509Certificate(clientCert).raw;
  return {
    clientCert, clientKey,
    tls: { ca, requestCert: true, rejectUnauthorized: true },
    accepts(req) {
      if (!req.socket.authorized || req.headers.authorization) return false;
      const leaf = req.socket.getPeerCertificate()?.raw;
      return leaf?.equals(expected) === true;
    },
  };
}
