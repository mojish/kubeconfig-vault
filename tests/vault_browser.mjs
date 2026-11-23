import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import { createInterface } from "node:readline";
import https from "node:https";
import { setTimeout as delay } from "node:timers/promises";
import { chromeConnection } from "./cdp.mjs";
import { testFreelens } from "./freelens_ui.mjs";

const cwd = new URL("../", import.meta.url).pathname;
const root = await mkdtemp(join(tmpdir(), "kube-vault-e2e-"));
const state = join(root, "state");
const children = [];
let driver;
const timer = setTimeout(() => { console.error("Vault integration test timed out."); process.exitCode = 1; for (const c of children) c.kill(); }, 300000);

function cli(...args) {
  const process = spawn("python3", ["kube_unlock.py", "--state-dir", state, ...args], { cwd, stdio: ["ignore", "pipe", "pipe"] });
  children.push(process);
  return result(process);
}
function result(child) {
  let stdout = "", stderr = "";
  child.stdout.on("data", data => { stdout += data; });
  child.stderr.on("data", data => { stderr += data; });
  const promise = new Promise((resolve, reject) => child.on("exit", code => code === 0 ? resolve(stdout.trim()) : reject(new Error(`Command failed (${code}): ${stderr}`))));
  promise.catch(() => {}); // Cleanup may terminate a still-waiting synthetic client.
  return promise;
}
function kubectl() {
  const child = spawn("/bin/kubectl", ["--kubeconfig", join(state, "current/kubeconfig"), "--cache-dir", join(root, "cache"), "get", "--raw=/version", "--request-timeout=30s"], { stdio: ["ignore", "pipe", "pipe"] });
  children.push(child);
  return result(child);
}
async function waitFor(fn, label) {
  for (let i = 0; i < 150; i++) { try { const value = await fn(); if (value) return value; } catch {} await delay(100); }
  throw new Error("Timed out: " + label);
}

try {
  driver = spawn("python3", ["tests/vault_driver.py", root], { cwd, stdio: ["pipe", "pipe", "pipe"] });
  children.push(driver);
  driver.stderr.on("data", data => process.stderr.write(data));
  const lines = createInterface({ input: driver.stdout });
  const iterator = lines[Symbol.asyncIterator]();
  const initial = JSON.parse((await iterator.next()).value);
  assert.equal(initial.ready, true);
  const control = async command => { driver.stdin.write(JSON.stringify({ command }) + "\n"); return JSON.parse((await iterator.next()).value); };
  const { call: cdp, events } = chromeConnection(join(root, "chrome"), children);
  const { targetId } = await cdp("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await cdp("Target.attachToTarget", { targetId, flatten: true });
  const call = (method, params = {}) => cdp(method, params, sessionId);
  const evaluate = async expression => {
    const value = await call("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
    if (value.exceptionDetails) throw new Error(value.exceptionDetails.text);
    return value.result.value;
  };
  await call("Page.enable");
  await call("Runtime.enable");
  await call("Network.enable");
  await call("WebAuthn.enable", { enableUI: false });
  const addAuthenticator = () => call("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", ctap2Version: "ctap2_1", transport: "usb", hasResidentKey: false,
    hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true,
  } });
  let { authenticatorId } = await addAuthenticator();

  async function complete(mode) {
    const job = await waitFor(async () => { const j = await control("job"); return j.url && j.mode === mode ? j : false; }, "browser job " + mode);
    await call("Page.navigate", { url: job.url });
    await waitFor(() => evaluate(`document.body.dataset.stage === '${mode}' && document.querySelector('#continue')?.disabled === false`), "unlock button");
    assert.equal(await evaluate("location.hash"), "");
    await evaluate("document.querySelector('#continue').click()");
    if (mode === "enroll") {
      await waitFor(() => evaluate("document.querySelector('#continue')?.textContent === 'Protect vault with this key'"), "registration");
      await evaluate("document.querySelector('#continue').click()");
    }
    try {
      await waitFor(() => evaluate("document.body.dataset.stage === 'passed'"), "successful unlock");
    } catch (err) {
      throw new Error(err.message + ": " + await evaluate("document.querySelector('#error')?.textContent"));
    }
    assert.equal(await evaluate("document.querySelector('#error').textContent"), "");
  }

  const importing = cli("import", initial.source);
  await complete("enroll");
  await importing;
  assert.equal(JSON.parse(await kubectl()).gitVersion, "v1.32.0");
  const expiry = JSON.parse(await cli("status")).expires;
  assert.equal(JSON.parse(await kubectl()).gitVersion, "v1.32.0");
  assert.equal(JSON.parse(await cli("status")).expires, expiry);
  assert.equal((await control("job")).url, null);
  console.log("PASS: browser enrollment, encrypted import, real kubectl against synthetic HTTPS API, shared fixed session.");

  if (process.argv.includes("--freelens-ui")) await testFreelens({ root, state, cwd, children, control, complete, cli });

  const proxy = spawn("/opt/Freelens/resources/x64/freelens-k8s-proxy", ["proxy", "--kubeconfig", join(state, "current/kubeconfig")], {
    env: { ...process.env, KUBECONFIG: join(state, "current/kubeconfig"), FREELENS_PROXY_CONTEXT: "synthetic",
      FREELENS_PROXY_API_PREFIX: "/synthetic-test", FREELENS_PROXY_KEY: await readFile(join(root, "test-server-key.pem"), "utf8"),
      FREELENS_PROXY_CERT: await readFile(join(root, "test-ca.pem"), "utf8") },
    stdio: ["ignore", "pipe", "pipe"],
  });
  children.push(proxy);
  let proxyOutput = "";
  proxy.stdout.on("data", data => { proxyOutput += data; });
  proxy.stderr.on("data", data => { proxyOutput += data; });
  const port = await waitFor(() => proxyOutput.match(/127\.0\.0\.1:(\d+)/)?.[1], "Freelens proxy listener");
  const proxyRequest = () => {
    const promise = new Promise((resolve, reject) => {
      https.get({ hostname: "127.0.0.1", port, path: "/synthetic-test/version", ca: certificate, timeout: 30000 }, response => {
        let body = ""; response.on("data", data => { body += data; });
        response.on("end", () => response.statusCode === 200 ? resolve(JSON.parse(body)) : reject(new Error("Freelens proxy status " + response.statusCode)));
      }).on("error", reject).on("timeout", function () { this.destroy(new Error("Proxy request timed out")); });
    });
    promise.catch(() => {});
    return promise;
  };
  const certificate = await readFile(join(root, "test-ca.pem"));
  assert.equal((await proxyRequest()).gitVersion, "v1.32.0");
  console.log("PASS: Freelens 2.1.0 bundled Kubernetes proxy uses the shared unlocked session.");

  await cli("lock");
  const coldA = kubectl(), coldB = kubectl();
  await complete("unlock");
  await Promise.all([coldA, coldB]);
  console.log("PASS: concurrent cold kubectl requests share one browser unlock.");

  // A fresh proxy has no in-process client-go token cache.
  proxy.kill();

  const editPath = await cli("config", "unlock");
  const edited = (await readFile(editPath, "utf8")) + "# Edited normally.\n";
  await writeFile(editPath, edited);
  await cli("config", "lock");
  assert.equal(JSON.parse(await cli("status")).unlocked, false);
  const afterEdit = kubectl();
  await complete("unlock");
  await afterEdit;
  const exported = join(root, "export.yaml");
  await cli("export", exported);
  assert.equal(await readFile(exported, "utf8"), edited);
  console.log("PASS: normal-file edit, encrypt-and-lock, exact source export, unchanged token works.");

  await control("restart");
  const restarted = kubectl();
  await complete("unlock");
  await restarted;
  await control("expire");
  const expired = kubectl();
  await complete("unlock");
  await expired;
  console.log("PASS: daemon restart and session expiration require fresh hardware authentication.");

  const adding = cli("key", "add");
  await complete("unlock");
  await call("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
  ({ authenticatorId } = await addAuthenticator());
  await complete("enroll");
  await adding;
  assert.equal(JSON.parse(await cli("status")).keys, 2);
  await cli("lock");
  const recovered = kubectl();
  const job = await waitFor(async () => (await control("job")).url, "backup-key unlock");
  await call("Page.navigate", { url: job });
  await waitFor(() => evaluate("document.body.dataset.stage === 'unlock' && document.querySelector('#continue')?.disabled === false"), "backup-key button");
  await evaluate("document.querySelector('#key').value='1'; document.querySelector('#continue').click()");
  await waitFor(() => evaluate("document.body.dataset.stage === 'passed'"), "backup-key recovery");
  await recovered;
  console.log("PASS: separately registered second security key recovers the same encrypted token.");

  for (const generation of await readdir(join(state, "generations"))) {
    for (const file of ["vault.json", "kubeconfig"]) {
      const content = await readFile(join(state, "generations", generation, file), "utf8");
      assert.ok(!content.includes("synthetic-integration-token-never-a-real-credential"));
    }
  }
  async function scan(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await scan(path);
      else if (entry.isFile()) assert.ok(!(await readFile(path)).includes(Buffer.from("synthetic-integration-token-never-a-real-credential")), `Plaintext synthetic token in ${path}`);
    }
  }
  if (process.argv.includes("--freelens-ui")) {
    await scan(join(root, "freelens-storage"));
    await scan(join(root, "freelens-electron"));
    console.log("PASS: no plaintext synthetic token in the isolated Freelens profile or logs.");
  }
  assert.deepEqual(await evaluate("[localStorage.length, sessionStorage.length]"), [0, 0]);
  for (const event of events.filter(e => e.method === "Network.requestWillBeSent")) {
    assert.ok(!JSON.stringify(event.params.request).includes("synthetic-integration-token-never-a-real-credential"));
  }
  assert.ok((await control("calls")).calls.every(c => c.authenticated));
  assert.equal(events.filter(e => e.method === "Runtime.exceptionThrown").length, 0);
  console.log("PASS: no plaintext token in stored generations, generated configs, or browser requests/storage.");
  await control("stop");
} finally {
  clearTimeout(timer);
  for (const child of children.reverse()) {
    if (child.exitCode === null) {
      const done = once(child, "exit"); child.kill();
      await Promise.race([done, delay(2000)]);
      if (child.exitCode === null) child.kill("SIGKILL");
    }
  }
  await rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
}
