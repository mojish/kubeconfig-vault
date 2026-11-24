import { spawn } from "node:child_process";

export function devtoolsPipe(child, {recordEvents = false, timeoutMs = 0} = {}) {
  const pending = new Map(), events = [];
  let sequence = 0, buffer = Buffer.alloc(0), closed;
  const close = () => {
    closed = new Error("Browser debugging pipe closed");
    for (const p of pending.values()) { clearTimeout(p.timer); p.reject(closed); }
    pending.clear();
  };
  child.once("exit", close);
  child.once("error", close);
  child.stdio[3].on("error", close);
  child.stdio[4].on("end", close);
  child.stdio[4].on("data", chunk => {
    buffer = Buffer.concat([buffer, chunk]);
    let end;
    while ((end = buffer.indexOf(0)) !== -1) {
      const message = JSON.parse(buffer.subarray(0, end).toString());
      buffer = buffer.subarray(end + 1);
      if (!message.id) {
        if (recordEvents) events.push(message);
        continue;
      }
      const p = pending.get(message.id);
      if (!p) continue;
      pending.delete(message.id);
      clearTimeout(p.timer);
      if (message.error) {
        const error = new Error("Browser rejected debugging command");
        error.code = message.error.code;
        p.reject(error);
      } else p.resolve(message.result);
    }
  });
  function call(method, params = {}, sessionId) {
    return new Promise((resolve, reject) => {
      if (closed) { reject(closed); return; }
      const id = ++sequence;
      const timer = timeoutMs && setTimeout(() => {
        pending.delete(id);
        reject(new Error("Timed out waiting for browser debugging command"));
      }, timeoutMs);
      pending.set(id, {resolve, reject, timer});
      child.stdio[3].write(JSON.stringify({id, method, params, ...(sessionId ? {sessionId} : {})}) + "\0");
    });
  }
  return { call, events };
}

export function chromeConnection(directory, children) {
  const executable = process.env.KUBE_UNLOCK_TEST_CHROME || (process.platform === "darwin"
    ? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" : "google-chrome");
  const browser = spawn(executable, ["--headless=new", `--user-data-dir=${directory}`, "--remote-debugging-pipe",
    "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update",
    "--disable-sync", "--password-store=basic", "about:blank"], { stdio: ["ignore", "ignore", "ignore", "pipe", "pipe"] });
  children.push(browser);
  return devtoolsPipe(browser, {recordEvents:true});
}
