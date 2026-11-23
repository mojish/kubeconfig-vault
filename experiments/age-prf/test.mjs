// Only emulated authenticators, a disposable Chrome profile, and a fixed dummy
// payload. No kubeconfig, vault, hardware, user browser profile, or cluster access.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { build } from "esbuild";
import { chromeConnection } from "../../tests/cdp.mjs";

const cwd = fileURLToPath(new URL(".", import.meta.url));
const directory = await mkdtemp(join(tmpdir(), "ku-age-prf-"));
const children = [];
let server;
const timeout = setTimeout(() => {
  console.error("Synthetic age experiment timed out.");
  for (const child of children) child.kill("SIGKILL");
  server?.closeAllConnections();
  server?.close();
  process.exitCode = 1;
}, 90000);

try {
  const executable = join(directory, "age-driver");
  const compiled = spawnSync("go", ["build", "-o", executable, "."], {
    cwd, encoding: "utf8", timeout: 60000,
    env: { ...process.env, GOTOOLCHAIN: "local", GOPROXY: "off",
      GOPATH: process.env.GOPATH || join(tmpdir(), "kube-unlock-go-path"),
      GOCACHE: process.env.GOCACHE || join(tmpdir(), "kube-unlock-go-cache") },
  });
  if (compiled.status !== 0) throw new Error("Native test build failed: " + (compiled.error?.message || compiled.stderr));
  const bundle = await build({ absWorkingDir: cwd, entryPoints: ["bridge.mjs"], bundle: true,
    write: false, format: "esm", platform: "browser", target: "es2023", legalComments: "inline" });
  const script = bundle.outputFiles[0].contents;
  server = createServer((request, response) => {
    if (request.headers.host !== `localhost:${server.address().port}` || request.method !== "GET") {
      response.writeHead(403).end(); return;
    }
    const path = request.url;
    if (path !== "/" && path !== "/bridge.js") { response.writeHead(404).end(); return; }
    response.writeHead(200, {
      "Content-Type": path === "/" ? "text/html" : "text/javascript",
      "Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy": "default-src 'none'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'",
    });
    response.end(path === "/" ? '<!doctype html><title>Synthetic age test</title><script type="module" src="/bridge.js"></script>' : script);
  });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const origin = `http://localhost:${server.address().port}`;

  const driver = spawn(executable, [], { stdio: ["pipe", "pipe", "pipe"] });
  children.push(driver);
  const lines = createInterface({ input: driver.stdout })[Symbol.asyncIterator]();
  const receive = async () => {
    const next = await lines.next();
    if (next.done) throw new Error("Synthetic native driver exited unexpectedly.");
    return JSON.parse(next.value);
  };
  const send = value => driver.stdin.write(JSON.stringify(value) + "\n");
  assert.equal((await receive()).event, "ready");

  const { call: cdp, events } = chromeConnection(join(directory, "chrome"), children);
  const { targetId } = await cdp("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await cdp("Target.attachToTarget", { targetId, flatten: true });
  const call = (method, params = {}) => cdp(method, params, sessionId);
  const evaluate = async expression => {
    const value = await call("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true, userGesture: true });
    // Suppress exception values: real integrations must never echo input keys.
    if (value.exceptionDetails) throw new Error("Synthetic browser operation failed.");
    return value.result.value;
  };
  const loaded = async () => {
    for (let i = 0; i < 100; i++) {
      if (await evaluate("typeof window.ageExperiment !== 'undefined'")) return;
      await delay(50);
    }
    throw new Error("Synthetic browser module did not load.");
  };
  await call("Page.enable");
  await call("Runtime.enable");
  await call("Network.enable");
  await call("WebAuthn.enable", { enableUI: false });
  const authenticator = options => call("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", ctap2Version: "ctap2_1", transport: "usb", hasResidentKey: false,
    hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true,
    ...options,
  } });
  const { authenticatorId } = await authenticator({});
  await call("Page.navigate", { url: origin });
  await loaded();
  const identity = await evaluate("window.ageExperiment.enroll()");
  assert.ok(identity.startsWith("AGE-PLUGIN-FIDO2PRF-1"));

  const browserCall = (method, ...args) => evaluate(`window.ageExperiment.${method}(${args.map(a => JSON.stringify(a)).join(",")})`);
  let lastStanzas;
  const operation = async (op, ciphertext) => {
    send({ op, ciphertext });
    for (;;) {
      const message = await receive();
      if (message.event === "wrap") {
        try { send({ stanzas: await browserCall("wrap", identity, message.fileKey) }); }
        catch { send({ error: "browser operation failed" }); }
      } else if (message.event === "unwrap") {
        lastStanzas = message.stanzas;
        try { send({ fileKey: await browserCall("unwrap", identity, message.stanzas) }); }
        catch { send({ error: "browser operation failed" }); }
      } else return message;
    }
  };

  const first = await operation("seal");
  assert.equal(first.event, "sealed");
  assert.equal((await operation("open", first.ciphertext)).matched, true);
  console.log("PASS: native age payload, Typage WebAuthn wrapping and unwrapping.");
  const initialLoader = (await call("Page.getFrameTree")).frameTree.frame.loaderId;
  await call("Page.reload");
  for (let i = 0; i < 100; i++) {
    if ((await call("Page.getFrameTree")).frameTree.frame.loaderId !== initialLoader) break;
    await delay(50);
  }
  assert.notEqual((await call("Page.getFrameTree")).frameTree.frame.loaderId, initialLoader);
  await loaded();
  assert.equal((await operation("open", first.ciphertext)).matched, true);
  assert.deepEqual(await evaluate("[localStorage.length, sessionStorage.length]"), [0, 0]);
  console.log("PASS: a new browser document unlocks with no browser storage.");

  const second = await operation("seal");
  assert.equal(second.event, "sealed");
  assert.notEqual(first.ciphertext, second.ciphertext);
  assert.equal((await operation("captured-key", first.ciphertext)).matched, true);
  assert.notEqual((await operation("captured-key", second.ciphertext)).matched, true);
  assert.equal((await operation("open", second.ciphertext)).matched, true);
  console.log("PASS: an earlier file key cannot decrypt a later saved generation.");

  const modified = Buffer.from(second.ciphertext, "base64");
  modified[modified.length - 1] ^= 1;
  assert.notEqual((await operation("open", modified.toString("base64"))).matched, true);
  assert.notEqual((await operation("recover", modified.toString("base64"))).matched, true);
  assert.notEqual((await operation("wrong-recovery", second.ciphertext)).matched, true);
  console.log("PASS: altered ciphertext and an unrelated recovery key are rejected.");

  await call("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
  // These commands bypass browser callbacks entirely, proving recovery needs no token.
  for (const file of [first, second]) assert.equal((await operation("recover", file.ciphertext)).matched, true);
  console.log("PASS: offline recovery opens both generations with no authenticator.");

  const wrong = await authenticator({});
  const wrongIdentity = await evaluate("window.ageExperiment.enroll()");
  assert.equal(await evaluate(`window.ageExperiment.unwrap(${JSON.stringify(wrongIdentity)}, ${JSON.stringify(lastStanzas)}).then(() => false, () => true)`), true);
  console.log("PASS: a different authenticator cannot unwrap the original file key.");
  await call("WebAuthn.removeVirtualAuthenticator", { authenticatorId: wrong.authenticatorId });
  await authenticator({ hasPrf: false });
  assert.equal(await evaluate("window.ageExperiment.enroll().then(() => false, () => true)"), true);
  console.log("PASS: enrollment rejects a security key without PRF.");
  const requests = events.filter(e => e.method === "Network.requestWillBeSent").map(e => e.params.request);
  assert.ok(requests.every(r => r.url.startsWith(origin + "/")));
  assert.ok(requests.every(r => r.method === "GET"));
  assert.ok(events.filter(e => e.method === "Runtime.exceptionThrown").length === 0);
  send({ op: "stop" });
  await once(driver, "exit");
  console.log("PASS: locally bundled assets only; no payload or keys in HTTP requests.");
} finally {
  clearTimeout(timeout);
  for (const child of children.reverse()) {
    if (child.exitCode === null && child.signalCode === null) {
      const exited = once(child, "exit");
      child.kill();
      await Promise.race([exited, delay(3000)]);
      if (child.exitCode === null && child.signalCode === null) {
        child.kill("SIGKILL"); await exited;
      }
    }
  }
  if (server?.listening) {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
  await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
}
