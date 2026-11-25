// Manual hardware qualification. No DevTools, virtual authenticator, or real config.
import assert from "node:assert/strict";
import { dummyAPI } from "./test-support/dummy-api.mjs";
import { captureProcess } from "./test-support/captured-process.mjs";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { lstat, mkdir, mkdtemp, readFile, writeFile, rm, stat } from "node:fs/promises";
import https from "node:https";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

const flags = process.argv.slice(2);
if (new Set(flags).size !== flags.length) throw new Error("Repeat each option at most once");
const useCertificate = flags.includes("--client-certificate");
const mode = flags.filter(flag => flag !== "--client-certificate").join(" ");
if (!["", "--preflight-only", "--keep-key-connected", "--macos-freelens", "--serve-fixture"].includes(mode))
  throw new Error("Choose --preflight-only, --keep-key-connected, --macos-freelens, or --serve-fixture");
const preflightOnly = mode === "--preflight-only";
const macGUI = mode === "--macos-freelens";
if (macGUI && (process.platform !== "darwin" || !process.env.KUBE_UNLOCK_TEST_BINARY))
  throw new Error("--macos-freelens needs macOS and KUBE_UNLOCK_TEST_BINARY pointing to your downloaded executable");
const keepKeyConnected = macGUI || mode === "--keep-key-connected";
process.umask(0o077);
// Keep the Unix-domain socket pathname within macOS's shorter limit.
const root = await mkdtemp(join(process.platform === "darwin" ? "/tmp" : tmpdir(), "kua-physical-"));
const state = join(root, "state"), profile = join(root, "chrome");
const guiHome = join(root, "home"), source = join(guiHome, ".kube", "config");
const recovery = join(root, "offline-key");
const launcher = join(root, macGUI ? "open" : "browser"), launches = join(root, "launches");
const executable = resolve(process.env.KUBE_UNLOCK_TEST_BINARY || fileURLToPath(new URL("./kubeconfig-vault", import.meta.url)));
const freelens = process.env.KUBE_UNLOCK_TEST_FREELENS || "/Applications/Freelens.app/Contents/MacOS/Freelens";
const chrome = process.env.KUBE_UNLOCK_TEST_CHROME || (process.platform === "darwin"
  ? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" : "google-chrome");
const chromeArgs = [`--user-data-dir=${profile}`, "--no-first-run", "--no-default-browser-check",
  "--disable-sync", "--disable-background-networking", "--disable-component-update", "--password-store=basic"];
const token = useCertificate ? undefined : "synthetic-" + randomBytes(24).toString("hex");
const children = [], abort = new AbortController();
let server, terminal, authenticatedNamespaceLists = 0, rejectedCredentials = 0, stage = "preflight";
const interrupt = () => abort.abort();
process.on("SIGINT", interrupt);
process.on("SIGTERM", interrupt);
const deadline = mode === "--serve-fixture" ? undefined : setTimeout(interrupt, (macGUI ? 30 : 15) * 60_000);

function start(command, args, env = process.env) {
  const child = spawn(command, args, { env, stdio: ["ignore", "pipe", "pipe"] });
  children.push(child);
  // Keep errors captured even when a long-lived child is not currently awaited.
  const completed = captureProcess(child, 65536).promise.catch(() => ({
    code: -1, stdout: "", stderr: "child startup failed",
  }));
  return { child, completed };
}
async function run(command, args, timeout = 360_000) {
  abort.signal.throwIfAborted();
  const task = start(command, args);
  let timer, cancel;
  const interrupted = new Promise((_, reject) => {
    cancel = () => { task.child.kill(); reject(new Error("test interrupted")); };
    abort.signal.addEventListener("abort", cancel, { once: true });
    timer = setTimeout(cancel, timeout);
  });
  try {
    const result = await Promise.race([task.completed, interrupted]);
    // Deliberately do not print child output, configs, or browser launch details.
    if (result.code !== 0) throw new Error("test command failed");
    return result.stdout;
  } finally {
    clearTimeout(timer);
    abort.signal.removeEventListener("abort", cancel);
  }
}
const options = macGUI ? ["--state-dir", state] : ["--state-dir", state, "--browser", launcher];
const cli = (...args) => run(executable, [...options, ...args]);
const status = async () => JSON.parse(await cli("status"));
async function launchCount() {
  return (await readFile(launches, "utf8").catch(() => "")).split("\n").filter(Boolean).length;
}
async function kube(config, timeout = 330_000) {
  const output = await run(process.env.KUBE_UNLOCK_TEST_KUBECTL || "kubectl", [
    "--kubeconfig", config, "--cache-dir", join(root, "kubecache"),
    "get", "--raw=/version", "--request-timeout=5m",
  ], timeout);
  assert.ok(JSON.parse(output).gitVersion === "v1.32.0", "dummy API response was not received");
}
async function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null || !child.pid) return;
  const exited = once(child, "exit").catch(() => {});
  child.kill("SIGTERM");
  await Promise.race([exited, delay(2000)]);
  if (child.exitCode === null && child.signalCode === null) {
    child.kill("SIGKILL");
    await exited;
  }
}

async function waitFor(check, timeout) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    abort.signal.throwIfAborted();
    if (await check()) return;
    await delay(250, undefined, { signal: abort.signal });
  }
  throw new Error("stage timed out");
}

async function checkFreelens(reconnect) {
  stage = reconnect ? "Freelens reconnect after lock" : "Freelens first connection";
  assert.ok(JSON.parse(await cli("lock")).fully_locked, "helper did not lock");
  const initialLists = authenticatedNamespaceLists, before = await launchCount();
  const gui = start(freelens, ["--user-data-dir=" + join(root, "freelens")], {
    ...process.env, HOME: guiHome, KUBECONFIG: source,
  });
  console.log(reconnect ? "WAIT: Reopen the synthetic cluster and its Namespaces view after the lock."
    : "WAIT: Open the synthetic cluster in Freelens. If it is missing, add this file by path: " + source);
  console.log("Complete the USB security-key unlock, then open Namespaces and look for vault-test.");
  await waitFor(async () => {
    if (gui.child.exitCode !== null || gui.child.signalCode !== null || !gui.child.pid)
      throw new Error("Freelens exited before making a request");
    return authenticatedNamespaceLists > initialLists && await launchCount() === before + 1 && (await status()).unlocked;
  }, 5 * 60_000);
  const session = await status();
  // Only run kubectl after recording the GUI's own authenticated request.
  await kube(source, 15_000);
  assert.ok(await launchCount() === before + 1 && (await status()).expires_at === session.expires_at);
  console.log("PASS: " + stage + " fetched the namespace list; kubectl reused its session.");
  console.log("WAIT: Quit the test Freelens app with Command-Q to continue.");
  await waitFor(() => gui.child.exitCode !== null || gui.child.signalCode !== null, 2 * 60_000);
}

try {
  stage = "release executable --version";
  const version = (await run(executable, ["--version"], 15_000)).trim();
  assert.match(version, /^kubeconfig-vault (?:v\d+\.\d+\.\d+|dev)$/);
  if (macGUI) {
    assert.match(version, /^kubeconfig-vault v/);
    stage = "Freelens executable";
    assert.ok((await stat(freelens)).isFile());
  }
  console.log(`PASS: ${version} executed on ${process.platform}/${process.arch}.`);
  stage = "local TLS fixture";
  const cert = join(root, "cert.pem"), key = join(root, "key.pem");
  const tlsConfig = join(root, "openssl.cnf");
  await writeFile(tlsConfig, "[req]\ndistinguished_name=dn\nx509_extensions=cert_ext\n[dn]\n[cert_ext]\nsubjectAltName=IP:127.0.0.1\n");
  const made = spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", key, "-out", cert, "-subj", "/CN=localhost", "-days", "1",
    "-config", tlsConfig], { encoding: "utf8", timeout: 15000 });
  assert.ok(made.status === 0, "dummy TLS fixture failed");
  const certificate = await readFile(cert);
  // Only the certificate trial needs the Go-generated client fixture.
  const identity = useCertificate
    ? await (await import("./test-support/client-certificate.mjs")).clientCertificateFixture(root)
    : undefined;
  const user = identity ? {
    "client-certificate-data": identity.clientCert.toString("base64"),
    "client-key-data": identity.clientKey.toString("base64"),
  } : { token };
  function checkProjection(text) {
    assert.ok(!text.includes(identity ? user["client-key-data"] : token), "credential found in client config");
    assert.ok(!text.includes("client-key-data"), "private key field found in client config");
  }
  stage = "starting the loopback HTTPS API";
  server = https.createServer({ key: await readFile(key), cert: certificate, ...identity?.tls }, (req, res) => {
    const permitted = identity ? identity.accepts(req) : req.headers.authorization === `Bearer ${token}`;
    if (!permitted) {
      rejectedCredentials++;
      res.writeHead(401).end();
      return;
    }
    const uri = new URL(req.url, "https://localhost");
    const result = dummyAPI(req.method, uri.pathname);
    if (!result) { res.writeHead(404).end(); return; }
    if (uri.searchParams.get("watch") === "true") { res.writeHead(200, { "Content-Type": "application/json" }).end(); return; }
    if (result.kind === "NamespaceList") authenticatedNamespaceLists++;
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(result));
  });
  if (identity) server.on("tlsClientError", () => { rejectedCredentials++; });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const original = JSON.stringify({ apiVersion: "v1", kind: "Config",
    clusters: [{ name: "synthetic", cluster: { server: `https://127.0.0.1:${server.address().port}`,
      "certificate-authority-data": certificate.toString("base64") } }],
    users: [{ name: "synthetic", user }],
    contexts: ["synthetic", "alternate"].map(name => ({ name, context: { cluster: "synthetic", user: "synthetic" } })),
    "current-context": "synthetic" });
  stage = "kubectl against the test API";
  await mkdir(join(guiHome, ".kube"), { recursive: true });
  await writeFile(source, original, { mode: 0o600, flag: "wx" });
  await kube(source, 15_000);
  const namespaces = JSON.parse(await run(process.env.KUBE_UNLOCK_TEST_KUBECTL || "kubectl", [
    "--kubeconfig", source, "--cache-dir", join(root, "kubecache"), "get", "--raw=/api/v1/namespaces",
  ], 15_000));
  assert.equal(namespaces.items[0].metadata.name, "vault-test");
  for (const path of ["/api/v1/pods", "/api/v1/namespaces/vault-test/pods"]) {
    const pods = JSON.parse(await run(process.env.KUBE_UNLOCK_TEST_KUBECTL || "kubectl", [
      "--kubeconfig", source, "get", "--raw=" + path,
    ], 15_000));
    assert.equal(pods.kind, "PodList");
    assert.deepEqual(pods.items, []);
  }
  // Prove that this fixture actually needs its selected credential.
  const invalid = JSON.parse(original);
  invalid.users[0].user = { token: "deliberately-invalid" };
  const invalidPath = join(root, "invalid-config");
  await writeFile(invalidPath, JSON.stringify(invalid), { mode: 0o600, flag: "wx" });
  const beforeInvalid = rejectedCredentials;
  await assert.rejects(kube(invalidPath, 15_000));
  assert.ok(rejectedCredentials > beforeInvalid, "the fixture must observe a rejected credential");
  console.log(`PASS: kubectl fetched the version and vault-test namespace with ${identity ? "mutual TLS" : "a bearer token"}. The control without valid credentials failed.`);
  if (mode === "--serve-fixture") {
    stage = "serving the disposable test API";
    console.log("Disposable kubeconfig:", source);
    console.log("Copy this file to your test directory. Keep this terminal open during the trial. Press Ctrl-C to stop the API and remove the fixture.");
    if (!abort.signal.aborted) await once(abort.signal, "abort");
  } else if (!preflightOnly) {
    stage = "browser startup";
    if (!macGUI) {
      const browser = start(chrome, [...chromeArgs, "--new-window", "about:blank"]);
      await delay(1000, undefined, { signal: abort.signal });
      assert.ok(browser.child.pid && browser.child.exitCode === null, "isolated Chrome did not start");
    }
    // The Mac desktop mode exercises default browser selection through Launch Services.
    const opener = macGUI ? "/usr/bin/open" : chrome;
    const openArgs = macGUI ? [] : [...chromeArgs, "--new-window"];
    await writeFile(launcher, `#!/usr/bin/env node\nimport('node:child_process').then(async ({spawn})=>{\n` +
      `const fs=await import('node:fs'); const uri=process.argv[2];\n` +
      `if(new URL(uri).protocol!=='file:')process.exit(2);\n` +
      `fs.appendFileSync(${JSON.stringify(launches)},'open\\n',{mode:0o600});\n` +
      `const p=spawn(${JSON.stringify(opener)},[...${JSON.stringify(openArgs)},uri],{stdio:'ignore'});\n` +
      `p.on('error',()=>process.exit(2));p.on('exit',code=>process.exit(code??1));\n});\n`, { mode: 0o700, flag: "wx" });
    const daemon = start(executable, [...options, "serve"], macGUI ? { ...process.env, PATH: root + ":" + process.env.PATH } : process.env);
    for (let i = 0; i < 100; i++) {
      if (await stat(join(state, "session.sock")).then(s => s.isSocket(), () => false)) break;
      abort.signal.throwIfAborted();
      await delay(30);
    }
    assert.ok(daemon.child.exitCode === null, "test daemon did not start");
    await cli("recovery-key", "new", recovery);
    stage = "YubiKey enrollment and verification";
    console.log("WAIT: Complete all three numbered steps on the new Chrome enrollment page. Enter your PIN only in Chrome's security-key prompt.");
    await cli("import", source, "--recovery-key", recovery);
    assert.ok(await readFile(source, "utf8") === original, "dummy source changed");
    checkProjection(await readFile(join(state, "current", "kubeconfig"), "utf8"));
    assert.ok(await launchCount() === 1, "unexpected enrollment launch count");
    console.log("PASS: physical-key enrollment and native YubiKey/recovery verification completed; dummy source preserved.");
    const clientConfig = macGUI ? source : join(state, "current", "kubeconfig");
    if (macGUI) {
      stage = "attaching the test kubeconfig";
      console.log("WAIT: Approve the verification page to connect the temporary kubeconfig to its vault.");
      await cli("setup", source);
      assert.ok((await lstat(source)).isSymbolicLink(), "test kubeconfig was not linked");
      checkProjection(await readFile(source, "utf8"));
    }
    const beforeCold = await launchCount();
    stage = "cold kubectl unlock";
    console.log("WAIT: Approve the Kubernetes client request in the browser. You may leave the key connected throughout this test.");
    await kube(clientConfig);
    const cached = await status(), count = await launchCount();
    assert.ok(cached.unlocked && count === beforeCold + 1, "cold unlock did not establish a session");
    assert.ok(Date.parse(cached.expires_at) - Date.now() > 3500000, "expected one-hour session");
    console.log("PASS: real kubectl triggered physical-key browser unlock and reached the dummy API.");
    let removed = false;
    if (!keepKeyConnected) {
      stage = "waiting for optional removal check";
      terminal = createInterface({ input: process.stdin, output: process.stdout });
      let answer;
      do {
        answer = (await terminal.question("Type skip to leave the key connected, or unplugged only after removing it: ", { signal: abort.signal })).trim().toLowerCase();
      } while (!["unplugged", "skip"].includes(answer));
      removed = answer === "unplugged";
      terminal.close(); terminal = null;
    }
    if (!removed) console.log("SKIP: physical key-removal check. Continuing with the key connected.");
    stage = "cached kubectl access";
    for (const args of [["use-context","alternate"], ["set-context","--current","--namespace","vault-test"], ["use-context","synthetic"]]) {
      await run(process.env.KUBE_UNLOCK_TEST_KUBECTL || "kubectl", ["--kubeconfig",clientConfig,"config",...args], 15_000);
    }
    await kube(clientConfig, 15_000);
    await kube(clientConfig, 15_000);
    assert.ok(await launchCount() === count && (await status()).expires_at === cached.expires_at, "cache opened a browser or extended its deadline");
    console.log(`PASS: two new kubectl processes reused the session without a new browser or deadline extension (${removed ? "key removal confirmed" : "key left connected"}).`);
    if (macGUI) {
      await checkFreelens(false);
      await checkFreelens(true);
      stage = "decline a client unlock";
      await cli("lock");
      const beforeDecline = await launchCount();
      console.log("WAIT: Click Decline request on the vault page. Leave the YubiKey connected.");
      await assert.rejects(kube(source));
      assert.equal(await launchCount(), beforeDecline + 1);
      assert.equal((await status()).unlocked, false);
      console.log("PASS: declining the page rejected kubectl and left the helper locked.");
    }
    stage = "offline recovery";
    const beforeRecovery = await launchCount();
    assert.ok(JSON.parse(await cli("lock")).fully_locked, "helper did not lock");
    const recovered = join(root, "recovered");
    await cli("recover", join(state, "current", "vault.age"), "--key", recovery, "--out", recovered);
    await kube(recovered, 15_000);
    assert.ok(await launchCount() === beforeRecovery && !(await status()).unlocked, "recovery opened the browser or unlocked the helper");
    console.log(`PASS: offline recovery and recovered-config kubectl access succeeded with the helper locked (${removed ? "key removal confirmed" : "key left connected"}).`);
    await cli("stop");
    await daemon.completed;
    console.log("PASS: updated physical-key qualification completed.");
  }
} catch {
  console.error(`${abort.signal.aborted ? "CANCELLED" : "FAIL"}: ${stage}. No child output or credential values are printed. Test data will be removed.`);
  process.exitCode = abort.signal.aborted ? 130 : 1;
} finally {
  clearTimeout(deadline);
  terminal?.close();
  for (const child of children.reverse()) await stop(child);
  if (server?.listening) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
  await rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  process.off("SIGINT", interrupt); process.off("SIGTERM", interrupt);
  console.log("CLEANUP: test processes and temporary files removed.");
}
