// Manual hardware qualification. No DevTools, virtual authenticator, or real config.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, writeFile, rm, stat } from "node:fs/promises";
import https from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline/promises";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

const preflightOnly = process.argv.slice(2).join(" ") === "--preflight-only";
const keepKeyConnected = process.argv.slice(2).join(" ") === "--keep-key-connected";
if (process.argv.length > 2 && !preflightOnly && !keepKeyConnected) throw new Error("Supported options: --preflight-only or --keep-key-connected");
process.umask(0o077);
const root = await mkdtemp(join(tmpdir(), "kua-physical-"));
const state = join(root, "state"), profile = join(root, "chrome");
const source = join(root, "source"), recovery = join(root, "offline-key");
const launcher = join(root, "browser"), launches = join(root, "launches");
const executable = fileURLToPath(new URL("./kube-unlock-age", import.meta.url));
const chrome = process.env.KUBE_UNLOCK_TEST_CHROME || (process.platform === "darwin"
  ? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" : "google-chrome");
const chromeArgs = [`--user-data-dir=${profile}`, "--no-first-run", "--no-default-browser-check",
  "--disable-sync", "--disable-background-networking", "--disable-component-update", "--password-store=basic"];
const token = "SYNTHETIC-PHYSICAL-QUALIFICATION-TOKEN";
const children = [], abort = new AbortController();
let server, terminal, stage = "preflight";
const interrupt = () => abort.abort();
process.on("SIGINT", interrupt);
process.on("SIGTERM", interrupt);
const deadline = setTimeout(interrupt, 15 * 60_000);

function start(command, args) {
  const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
  children.push(child);
  let stdout = "", stderr = "";
  child.stdout.on("data", b => { stdout = (stdout + b).slice(-65536); });
  child.stderr.on("data", b => { stderr = (stderr + b).slice(-65536); });
  // Keep errors captured even when a long-lived child is not currently awaited.
  const completed = new Promise(resolve => {
    child.once("error", () => resolve({ code: -1, stdout: "", stderr: "child startup failed" }));
    child.once("exit", code => resolve({ code, stdout, stderr }));
  });
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
const cli = (...args) => run(executable, ["--state-dir", state, "--browser", launcher, ...args]);
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

try {
  assert.ok((await stat(executable)).isFile(), "build the age executable first");
  const cert = join(root, "cert.pem"), key = join(root, "key.pem");
  const made = spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", key, "-out", cert, "-subj", "/CN=localhost", "-days", "1",
    "-addext", "subjectAltName=IP:127.0.0.1"], { encoding: "utf8", timeout: 15000 });
  assert.ok(made.status === 0, "dummy TLS fixture failed");
  const certificate = await readFile(cert);
  server = https.createServer({ key: await readFile(key), cert: certificate }, (req, res) => {
    if (req.headers.authorization !== `Bearer ${token}`) { res.writeHead(401).end(); return; }
    if (new URL(req.url, "https://localhost").pathname !== "/version") { res.writeHead(404).end(); return; }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ gitVersion: "v1.32.0" }));
  });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const original = JSON.stringify({ apiVersion: "v1", kind: "Config",
    clusters: [{ name: "synthetic", cluster: { server: `https://127.0.0.1:${server.address().port}`,
      "certificate-authority-data": certificate.toString("base64") } }],
    users: [{ name: "synthetic", user: { token } }],
    contexts: [{ name: "synthetic", context: { cluster: "synthetic", user: "synthetic" } }],
    "current-context": "synthetic" });
  await writeFile(source, original, { mode: 0o600, flag: "wx" });
  await kube(source, 15_000);
  console.log("PASS: explicit dummy kubeconfig reaches the local HTTPS API, including kubectl timeout query parameters.");
  if (!preflightOnly) {
    stage = "browser startup";
    const browser = start(chrome, [...chromeArgs, "--new-window", "about:blank"]);
    await delay(1000, undefined, { signal: abort.signal });
    assert.ok(browser.child.pid && browser.child.exitCode === null, "isolated Chrome did not start");
    await writeFile(launcher, `#!${process.execPath}\nimport('node:child_process').then(async ({spawn})=>{\n` +
      `const fs=await import('node:fs'); const uri=process.argv[2];\n` +
      `if(new URL(uri).protocol!=='file:')process.exit(2);\n` +
      `fs.appendFileSync(${JSON.stringify(launches)},uri+'\\n',{mode:0o600});\n` +
      `const p=spawn(${JSON.stringify(chrome)},[...${JSON.stringify(chromeArgs)},'--new-window',uri],{stdio:'ignore'});\n` +
      `p.on('error',()=>process.exit(2));p.on('exit',code=>process.exit(code??1));\n});\n`, { mode: 0o700, flag: "wx" });
    const daemon = start(executable, ["--state-dir", state, "--browser", launcher, "serve"]);
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
    assert.ok(!(await readFile(join(state, "current", "kubeconfig"), "utf8")).includes(token), "dummy token present in generated config");
    assert.ok(await launchCount() === 1, "unexpected enrollment launch count");
    console.log("PASS: physical-key enrollment and native YubiKey/recovery verification completed; dummy source preserved.");
    stage = "cold kubectl unlock";
    console.log("WAIT: Complete the separate Unlock Kubernetes access page. You may leave the key connected throughout this test.");
    await kube(join(state, "current", "kubeconfig"));
    const cached = await status(), count = await launchCount();
    assert.ok(cached.unlocked && count === 2, "cold unlock did not establish a session");
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
    stage = "cached access and offline recovery";
    await kube(join(state, "current", "kubeconfig"), 15_000);
    await kube(join(state, "current", "kubeconfig"), 15_000);
    assert.ok(await launchCount() === count && (await status()).expires_at === cached.expires_at, "cache opened a browser or extended its deadline");
    console.log(`PASS: two new kubectl processes reused the session without a new browser or deadline extension (${removed ? "key removal confirmed" : "key left connected"}).`);
    assert.ok(JSON.parse(await cli("lock")).fully_locked, "helper did not lock");
    const recovered = join(root, "recovered");
    await cli("recover", join(state, "current", "vault.age"), "--key", recovery, "--out", recovered);
    await kube(recovered, 15_000);
    assert.ok(await launchCount() === count && !(await status()).unlocked, "recovery opened the browser or unlocked the helper");
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
  console.log("CLEANUP: test processes, browser profile, dummy vault/configs, and disposable recovery key removed.");
}
