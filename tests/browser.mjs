// Dependency-free Chrome DevTools test. Uses only a disposable browser profile.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import { setTimeout as delay } from "node:timers/promises";

const cwd = new URL("../", import.meta.url).pathname;
const directory = await mkdtemp(join(tmpdir(), "kube-unlock-browser-"));
const children = [];
const timeout = setTimeout(() => { console.error("Browser test timed out."); process.exitCode = 1; for (const p of children) p.kill(); }, 90000);
const apiPosts = [];
const jsErrors = [];
let screenshot;

async function startProbe() {
  const server = spawn("python3", ["probe.py"], { cwd, stdio: ["ignore", "pipe", "pipe"] });
  children.push(server);
  return await new Promise((resolve, reject) => {
    let output = "";
    server.stdout.on("data", chunk => {
      output += chunk.toString();
      const match = output.match(/Open (http:\/\/localhost:\d+)\//);
      if (match) resolve(match[1]);
    });
    server.once("error", reject);
    server.once("exit", code => reject(new Error(`Probe exited before becoming ready (${code}).`)));
    server.stderr.on("data", chunk => process.stderr.write(chunk));
  });
}

function chromeConnection() {
  const browser = spawn("/bin/google-chrome", [
    "--headless=new", `--user-data-dir=${directory}`, "--remote-debugging-pipe",
    "--no-first-run", "--no-default-browser-check", "--disable-background-networking",
    "--disable-component-update", "--disable-sync", "--password-store=basic", "about:blank",
  ], { stdio: ["ignore", "ignore", "pipe", "pipe", "pipe"] });
  children.push(browser);
  const pending = new Map();
  let id = 0, buffer = Buffer.alloc(0), logs = "";
  browser.stderr.on("data", chunk => { logs = (logs + chunk.toString()).slice(-4000); });
  browser.once("exit", code => {
    for (const job of pending.values()) job.reject(new Error(`Chrome exited (${code}): ${logs}`));
    pending.clear();
  });
  browser.stdio[4].on("data", chunk => {
    buffer = Buffer.concat([buffer, chunk]);
    let delimiter;
    while ((delimiter = buffer.indexOf(0)) !== -1) {
      const message = JSON.parse(buffer.subarray(0, delimiter).toString());
      buffer = buffer.subarray(delimiter + 1);
      if (message.id) {
        const job = pending.get(message.id);
        pending.delete(message.id);
        if (job) message.error ? job.reject(new Error(JSON.stringify(message.error))) : job.resolve(message.result);
      } else if (message.method === "Network.requestWillBeSent") {
        const request = message.params.request;
        if (request.method === "POST") apiPosts.push(request.postData || "");
      } else if (message.method === "Runtime.exceptionThrown") {
        jsErrors.push(message.params.exceptionDetails.text);
      }
    }
  });
  return (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const next = ++id;
    pending.set(next, { resolve, reject });
    browser.stdio[3].write(JSON.stringify({ id: next, method, params, ...(sessionId ? { sessionId } : {}) }) + "\0");
  });
}

try {
  const origin = await startProbe();
  const cdp = chromeConnection();
  const version = await cdp("Browser.getVersion");
  const { targetId } = await cdp("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await cdp("Target.attachToTarget", { targetId, flatten: true });
  const call = (method, params = {}) => cdp(method, params, sessionId);
  const evaluate = async expression => {
    const result = await call("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.text);
    return result.result.value;
  };
  async function waitFor(check, label) {
    for (let i = 0; i < 120; i++) {
      try { if (await check()) return; } catch {}
      await delay(100);
    }
    throw new Error(`Timed out: ${label}; page error: ${await evaluate("document.querySelector('#error')?.textContent")}`);
  }
  await call("Page.enable");
  await call("Runtime.enable");
  await call("Network.enable");
  await call("WebAuthn.enable", { enableUI: false });
  const authenticator = async hasPrf => await call("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", ctap2Version: "ctap2_1", transport: "usb", hasResidentKey: false,
    hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf,
  } });
  let { authenticatorId } = await authenticator(true);
  await call("Page.navigate", { url: `${origin}/` });
  await waitFor(() => evaluate("document.body.dataset.stage === 'new'"), "initial page");
  await evaluate("document.querySelector('#continue').click()");
  await waitFor(() => evaluate("document.body.dataset.stage === 'registered'"), "registration");
  const before = (await call("Page.getFrameTree")).frameTree.frame.loaderId;
  await evaluate("document.querySelector('#continue').click()");
  await waitFor(() => evaluate("document.body.dataset.stage === 'sealed'"), "encryption and reload");
  const after = (await call("Page.getFrameTree")).frameTree.frame.loaderId;
  assert.notEqual(before, after, "a new document must discard the sealing key");
  await evaluate("document.querySelector('#continue').click()");
  await waitFor(() => evaluate("document.body.dataset.stage === 'passed'"), "decryption");
  assert.deepEqual(await evaluate("[localStorage.length, sessionStorage.length]"), [0, 0]);
  for (const post of apiPosts) {
    const data = JSON.parse(post);
    assert.equal(data.credential?.clientExtensionResults, undefined);
    assert.equal(data.prf, undefined);
    assert.equal(data.secret, undefined);
    assert.equal(data.key, undefined);
  }
  await call("Emulation.setDeviceMetricsOverride", { width: 900, height: 850, deviceScaleFactor: 1, mobile: false });
  screenshot = join(directory, "passed.png");
  await writeFile(screenshot, Buffer.from((await call("Page.captureScreenshot", { format: "png" })).data, "base64"));
  // Preserve only this synthetic UI artifact outside the disposable profile.
  const screenshotPath = "/tmp/kube-unlock-probe-passed.png";
  await writeFile(screenshotPath, Buffer.from((await call("Page.captureScreenshot", { format: "png" })).data, "base64"));
  console.log(`PASS: ${version.product}: registration, PRF encryption, document reload, decryption, empty browser storage.`);
  console.log(`Synthetic UI screenshot: ${screenshotPath}`);

  await call("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
  ({ authenticatorId } = await authenticator(false));
  await call("Network.clearBrowserCookies");
  await call("Page.navigate", { url: `${origin}/` });
  await waitFor(() => evaluate("document.body.dataset.stage === 'new'"), "fresh unsupported-key session");
  await evaluate("document.querySelector('#continue').click()");
  await waitFor(() => evaluate("document.querySelector('#error').textContent.includes('PRF is unavailable')"), "unsupported PRF rejection");
  assert.equal(await evaluate("document.body.dataset.stage"), "new");
  assert.deepEqual(jsErrors, []);
  console.log("PASS: key without PRF is rejected; no JavaScript exceptions.");
} finally {
  clearTimeout(timeout);
  for (const child of children.reverse()) {
    if (child.exitCode === null) {
      const done = once(child, "exit");
      child.kill();
      await Promise.race([done, delay(3000)]);
      if (child.exitCode === null) child.kill("SIGKILL");
    }
  }
  await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
}
