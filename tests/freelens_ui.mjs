// Real installed Freelens, isolated from the user's entire home directory.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import { setTimeout as delay } from "node:timers/promises";
import { once } from "node:events";

async function waitFor(fn, label) {
  for (let i = 0; i < 300; i++) {
    try { const value = await fn(); if (value) return value; } catch {}
    await delay(100);
  }
  throw new Error("Freelens UI timeout: " + label);
}

function socketConnection(url) {
  const socket = new WebSocket(url);
  const pending = new Map();
  let id = 0;
  socket.addEventListener("message", event => {
    const message = JSON.parse(event.data);
    const item = pending.get(message.id);
    if (!item) return;
    pending.delete(message.id);
    message.error ? item.reject(new Error(JSON.stringify(message.error))) : item.resolve(message.result);
  });
  const ready = new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", reject, { once: true });
  });
  return { socket, call: async (method, params = {}, sessionId) => {
    await ready;
    return await new Promise((resolve, reject) => {
      const next = ++id;
      pending.set(next, { resolve, reject });
      socket.send(JSON.stringify({ id: next, method, params, ...(sessionId ? { sessionId } : {}) }));
    });
  } };
}

export async function testFreelens({ root, state, cwd, children, control, complete, cli }) {
  const profile = join(root, "freelens-storage", "Freelens");
  await mkdir(profile, { recursive: true });
  await writeFile(join(profile, "lens-user-store.json"), JSON.stringify({ preferences: {
    allowErrorReporting: false, syncKubeconfigEntries: [{ filePath: join(state, "current/kubeconfig") }],
  } }));
  const args = ["--die-with-parent", "--unshare-pid", "--ro-bind", "/", "/", "--tmpfs", homedir(),
    "--ro-bind", cwd, cwd, "--bind", root, root, "--proc", "/proc", "--dev-bind", "/dev", "/dev", "--chdir", root,
    "--", "/opt/Freelens/freelens", `--user-data-dir=${join(root, "freelens-electron")}`, "--remote-debugging-port=0",
    "--no-first-run", "--disable-background-networking", "--disable-component-update", "--password-store=basic"];
  const app = spawn("/bin/bwrap", args, { env: {
    ...process.env, FREELENS_INTEGRATION_TESTING_DIR: join(root, "freelens-storage"),
    KUBECONFIG: join(state, "current/kubeconfig"), NO_PROXY: "localhost,127.0.0.1", TMPDIR: root, GSETTINGS_BACKEND: "memory",
  }, stdio: ["ignore", "pipe", "pipe"] });
  children.push(app);
  let output = "";
  const capture = data => { output = (output + data).slice(-12000); };
  app.stdout.on("data", capture); app.stderr.on("data", capture);
  let connection, evaluate, call;
  try {
    const url = await waitFor(() => output.match(/DevTools listening on (ws:\/\/[^\s]+)/)?.[1], "debug connection");
    connection = socketConnection(url);
    const target = await waitFor(async () => (await connection.call("Target.getTargets")).targetInfos.find(t => t.type === "page" && t.url.startsWith("https://renderer.freelens.app:")), "main renderer");
    const { sessionId } = await connection.call("Target.attachToTarget", { targetId: target.targetId, flatten: true });
    call = (method, params = {}) => connection.call(method, params, sessionId);
    evaluate = async expression => {
      const response = await call("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
      if (response.exceptionDetails) throw new Error(response.exceptionDetails.text);
      return response.result.value;
    };
    await call("Runtime.enable");
    await waitFor(() => evaluate("document.body && document.body.innerText.length > 50"), "initial UI");
    // Navigation is deliberately through visible UI, not internal application APIs.
    await evaluate("Array.from(document.querySelectorAll('button,a,[role=button]')).find(e => /catalog/i.test(e.textContent+' '+e.getAttribute('title')+' '+e.getAttribute('aria-label')))?.click()");
    await waitFor(() => evaluate("document.body.innerText.includes('synthetic')"), "synthetic cluster discovery");
    await cli("lock");
    const point = await evaluate(`(() => {
      const node = Array.from(document.querySelectorAll('*')).find(e => e.children.length === 0 && e.textContent.trim() === 'synthetic' && e.getBoundingClientRect().width > 0);
      if (!node) throw new Error('Cluster row was not found');
      node.scrollIntoView(); const r = node.getBoundingClientRect(); return {x:r.x+r.width/2,y:r.y+r.height/2};
    })()`);
    for (const clickCount of [1, 2]) {
      await call("Input.dispatchMouseEvent", { type: "mousePressed", button: "left", clickCount, ...point });
      await call("Input.dispatchMouseEvent", { type: "mouseReleased", button: "left", clickCount, ...point });
    }
    await waitFor(async () => (await control("job")).mode === "unlock", "credential helper invoked by UI");
    await complete("unlock");
    await waitFor(async () => (await control("calls")).calls.some(c => c.path.includes("/api/v1/namespaces") && c.authenticated), "authenticated namespace request");
    assert.equal((await control("job")).url, null);
    // Cluster views can be separate Electron web contents rather than the shell page.
    const views = (await connection.call("Target.getTargets")).targetInfos;
    const clusterView = views.find(t => t.type === "page" && t.targetId !== target.targetId && t.url.startsWith("https://renderer.freelens.app:"));
    let capture = call;
    if (clusterView) {
      const attached = await connection.call("Target.attachToTarget", { targetId: clusterView.targetId, flatten: true });
      capture = (method, params = {}) => connection.call(method, params, attached.sessionId);
    }
    await capture("Page.enable");
    const picture = await capture("Page.captureScreenshot", { format: "png" });
    await writeFile("/tmp/kube-unlock-freelens.png", Buffer.from(picture.data, "base64"));
    console.log("PASS: isolated Freelens UI discovers the generated kubeconfig, unlocks through the helper, and requests namespaces with the original synthetic token.");
  } catch (error) {
    if (evaluate) console.error("Synthetic UI state:", (await evaluate("document.body.innerText")).slice(0, 2000));
    if (call) {
      const picture = await call("Page.captureScreenshot", { format: "png" });
      await writeFile("/tmp/kube-unlock-freelens-debug.png", Buffer.from(picture.data, "base64"));
    }
    console.error("Isolated Freelens diagnostic:", output.slice(-1500));
    throw error;
  } finally {
    connection?.socket.close();
    if (app.exitCode === null) {
      const closed = once(app, "close");
      app.kill();
      await Promise.race([closed, delay(3000)]);
      if (app.exitCode === null) app.kill("SIGKILL");
    }
  }
}
