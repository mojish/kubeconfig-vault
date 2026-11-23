import { spawn } from "node:child_process";

export function chromeConnection(directory, children) {
  const executable = process.env.KUBE_UNLOCK_TEST_CHROME || (process.platform === "darwin"
    ? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" : "google-chrome");
  const browser = spawn(executable, ["--headless=new", `--user-data-dir=${directory}`, "--remote-debugging-pipe",
    "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update",
    "--disable-sync", "--password-store=basic", "about:blank"], { stdio: ["ignore", "ignore", "pipe", "pipe", "pipe"] });
  children.push(browser);
  const pending = new Map(), events = [];
  let sequence = 0, buffer = Buffer.alloc(0), logs = "";
  browser.stderr.on("data", chunk => { logs = (logs + chunk).slice(-4000); });
  browser.once("exit", code => { for (const p of pending.values()) p.reject(new Error(`Chrome exited ${code}: ${logs}`)); pending.clear(); });
  browser.stdio[4].on("data", chunk => {
    buffer = Buffer.concat([buffer, chunk]);
    let end;
    while ((end = buffer.indexOf(0)) !== -1) {
      const message = JSON.parse(buffer.subarray(0, end).toString());
      buffer = buffer.subarray(end + 1);
      if (!message.id) { events.push(message); continue; }
      const p = pending.get(message.id);
      pending.delete(message.id);
      if (p) message.error ? p.reject(new Error(JSON.stringify(message.error))) : p.resolve(message.result);
    }
  });
  const call = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const id = ++sequence;
    pending.set(id, { resolve, reject });
    browser.stdio[3].write(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }) + "\0");
  });
  return { call, events };
}
