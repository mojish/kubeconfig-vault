// Drive only the Electron process launched with the fixture's private profile.
import { spawn } from "node:child_process";
import { mkdir, readlink, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { devtoolsPipe } from "./cdp.mjs";

// Evaluate in the application's own root or cluster frame. Return only the
// matching control's position or a boolean. Screens and credentials stay local.
function findInView(label, click, subframe) {
  const candidates = [...document.querySelectorAll("a,button,[role=button],span,div")];
  const element = candidates.filter(node =>
    node.getBoundingClientRect().width && [node.innerText?.trim(),
      node.getAttribute("title"), node.getAttribute("aria-label")].includes(label)).at(-1);
  if (!element) return false;
  if (!click) return true;
  if (subframe) {
    element.click();
    return true;
  }
  element.scrollIntoView({block:"center"});
  const box = element.getBoundingClientRect();
  return [box.x + box.width / 2, box.y + box.height / 2];
}

export async function displayNamespace({binary, root, kubeconfig, context, namespace, received,
  afterFirstView, signal}) {
  const home = join(root, "desktop-home");
  const profile = join(home, "profile");
  const config = join(home, ".kube", "config");
  const appData = join(home, "Freelens");
  const runtime = join(home, "runtime");
  for (const dir of [join(home, ".kube"), profile, appData, runtime]) {
    await mkdir(dir, {recursive:true, mode:0o700});
  }
  try { await symlink(kubeconfig, config); }
  catch (error) {
    if (error.code !== "EEXIST" || await readlink(config) !== kubeconfig) throw error;
  }
  // Freelens discovers ~/.kube via the OS account independently of HOME.
  // Seed the supported sync preference before each launch in its test profile.
  await writeFile(join(appData, "lens-user-store.json"), JSON.stringify({
    preferences:{syncKubeconfigEntries:[{filePath:config}]},
  }), {mode:0o600});
  const env = {HOME:home, KUBECONFIG:config, PATH:process.env.PATH,
    FREELENS_INTEGRATION_TESTING_DIR:home, XDG_RUNTIME_DIR:runtime,
    XDG_CONFIG_HOME:join(home,"config"), XDG_CACHE_HOME:join(home,"cache"), SHELL:"/bin/sh"};
  for (const name of ["DISPLAY","XAUTHORITY","TMPDIR","LANG"]) {
    if (process.env[name]) env[name] = process.env[name];
  }
  signal.throwIfAborted();
  const desktop = spawn(binary, ["--user-data-dir=" + profile, "--remote-debugging-pipe",
    "--disable-background-networking", "--disable-gpu", "--password-store=basic"],
    {env, detached:true, stdio:["ignore","ignore","ignore","pipe","pipe"]});
  const {call} = devtoolsPipe(desktop, {timeoutMs:15000});
  let exited = false;
  const stopped = new Promise(resolve => {
    const finish = () => { exited = true; resolve(); };
    desktop.once("exit", finish);
    desktop.once("error", finish);
  });
  function stopGroup(sig) {
    if (!desktop.pid) return;
    try { process.kill(-desktop.pid, sig); }
    catch (error) { if (error.code !== "ESRCH") throw error; }
  }
  const cancel = () => stopGroup("SIGTERM");
  signal.addEventListener("abort", cancel, {once:true});
  let targetId, sessionId, stage = "opening the desktop";
  const clicked = new Map();
  try {
    let deadline = Date.now() + 85_000;
    while (Date.now() < deadline && !exited) {
      signal.throwIfAborted();
      await delay(250);
      const {targetInfos} = await call("Target.getTargets");
      const target = targetInfos.find(t => t.type === "page" && !t.url.startsWith("devtools:"));
      if (!target) continue;
      let displayed = false;
      try {
        if (target.targetId !== targetId) {
          ({sessionId} = await call("Target.attachToTarget", {targetId:target.targetId,flatten:true}));
          targetId = target.targetId;
          stage = "loading the catalog";
        }
        const view = (method, params) => call(method, params, sessionId);
        const {frameTree} = await view("Page.getFrameTree");
        for (const frame of [undefined, ...(frameTree.childFrames || []).map(f => f.frame.id)]) {
          const world = frame && (await view("Page.createIsolatedWorld", {frameId:frame,worldName:"vault-fixture"})).executionContextId;
          const evaluate = async expression => (await view("Runtime.evaluate", {contextId:world,
            returnByValue:true, expression})).result?.value;
          const find = (label, click = false) => evaluate(
            `(${findInView})(${JSON.stringify(label)},${click},${Boolean(frame)})`);
          if (received() && await evaluate(
            `(document.body?.innerText || "").split("\\n").some(line => line.trim() === ${JSON.stringify(namespace)})`)) {
            displayed = true;
            break;
          }
          for (const label of ["Browse Clusters in Catalog", context, "Namespaces"]) {
            if ((clicked.get(label) || 0) > Date.now() - 3000 || !await find(label)) continue;
            const action = await find(label, true);
            if (Array.isArray(action)) {
              for (const type of ["mousePressed","mouseReleased"]) {
                await view("Input.dispatchMouseEvent", {type,x:action[0],y:action[1],button:"left",
                  clickCount:label === context ? 2 : 1});
              }
            }
            clicked.set(label, Date.now());
            stage = label === context ? "opening the test cluster" : label;
            break;
          }
        }
      } catch (error) {
        // Chromium replaces execution contexts and targets during navigation.
        if (error.code !== -32000 && error.code !== -32001) throw error;
        if (error.code === -32001) targetId = undefined;
      }
      if (displayed) {
        if (!afterFirstView) return;
        // Keep the same process open while the caller verifies renewal. A fresh
        // view must display an API response different from the initial one.
        stage = "checking the approved session";
        const next = await afterFirstView();
        afterFirstView = undefined;
        namespace = next.namespace;
        received = next.received;
        stage = "reloading the open desktop";
        await call("Page.reload", {ignoreCache:true}, sessionId);
        clicked.clear();
        deadline = Date.now() + 85_000;
      }
    }
    throw new Error("Freelens did not render the authenticated namespace; last stage was " + stage);
  } catch (error) {
    throw new Error("Freelens trial stopped while " + stage, {cause:error});
  } finally {
    signal.removeEventListener("abort", cancel);
    stopGroup("SIGTERM");
    if (!exited) await Promise.race([stopped, delay(3000)]);
    stopGroup("SIGKILL");
    await stopped;
  }
}
