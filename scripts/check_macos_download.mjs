// Hosted experiment using the published asset, the system Archive Utility and a fresh Chrome profile.
import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { devtoolsPipe } from "../age-app/test-support/cdp.mjs";

const [tag] = process.argv.slice(2);
if (process.platform !== "darwin" || process.env.RUNNER_ENVIRONMENT !== "github-hosted" ||
    process.env.GITHUB_ACTIONS !== "true" || !/^v\d+\.\d+\.\d+$/.test(tag || "")) {
  throw new Error("Use the public-install workflow on a hosted Mac with a release tag");
}
const cpu = {x64:"amd64", arm64:"arm64"}[process.arch];
if (!cpu) throw new Error("Unsupported runner architecture");
const repository = "mojish/kubeconfig-vault";
const asset = `kubeconfig-vault-darwin-${cpu}.tar.gz`;
const root = await mkdtemp(join(tmpdir(), "kcv-download-"));
const downloads = join(root, "Downloads"), archive = join(downloads, asset);
const clean = {PATH:"/usr/bin:/bin:/usr/sbin:/sbin", HOME:root, TMPDIR:tmpdir(), LANG:"C"};
const hash = data => createHash("sha256").update(data).digest("hex");

function run(executable, args, options = {}) {
  return spawnSync(executable, args, {cwd:root, env:clean, encoding:"utf8",
    stdio:["ignore","pipe","pipe"], timeout:15000, killSignal:"SIGKILL", ...options});
}
function marked(path) {
  const result = run("/usr/bin/xattr", [path]);
  if (result.status !== 0) throw new Error("Could not inspect quarantine attributes");
  return result.stdout.split("\n").includes("com.apple.quarantine");
}

async function browserDownload() {
  await mkdir(downloads, {mode:0o700});
  const chrome = spawn("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    ["--headless=new", "--remote-debugging-pipe", "--user-data-dir=" + join(root,"profile"),
     "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-sync",
     "--password-store=basic", "--use-mock-keychain", "about:blank"],
    {cwd:root, env:clean, stdio:["ignore","ignore","ignore","pipe","pipe"]});
  const stopped = new Promise(resolve => { chrome.once("exit", resolve); chrome.once("error", resolve); });
  const pipe = devtoolsPipe(chrome, {recordEvents:true, getTimeoutMs:() => 30_000});
  const call = (method, params, id) => pipe.call(method, params, id).catch(() => {
    throw new Error("The disposable Chrome instance did not complete " + method);
  });
  try {
    const version = await call("Browser.getVersion");
    console.log("Download browser:", version.product);
    await call("Browser.setDownloadBehavior", {behavior:"allow", downloadPath:downloads, eventsEnabled:true});
    const {targetId} = await call("Target.createTarget", {url:"about:blank"});
    const {sessionId} = await call("Target.attachToTarget", {targetId, flatten:true});
    // A navigation served as an attachment may never commit a document.
    // Use the download event as the completion signal.
    let navigationIssue;
    void call("Page.navigate", {url:`https://github.com/${repository}/releases/download/${tag}/${asset}`}, sessionId)
      .then(result => { navigationIssue = result.errorText; }, error => { navigationIssue = error.message; });
    const deadline = Date.now() + 90000;
    while (Date.now() < deadline) {
      if (pipe.events.some(e => e.method === "Browser.downloadProgress" && e.params.state === "completed")) return;
      if (pipe.events.some(e => e.method === "Browser.downloadProgress" && e.params.state === "canceled")) break;
      await delay(250);
    }
    throw new Error("Chrome did not finish the release download (" + (navigationIssue || "no completion event") + ")");
  } finally {
    if (chrome.exitCode === null && chrome.signalCode === null) chrome.kill("SIGTERM");
    await Promise.race([stopped, delay(2500)]);
    if (chrome.exitCode === null && chrome.signalCode === null) chrome.kill("SIGKILL");
    await stopped;
  }
}

async function expandedBinary(expected) {
  // Archive Utility may expand an archive into a folder or next to the archive.
  for (const entry of await readdir(downloads, {withFileTypes:true})) {
    if (entry.name.startsWith(".")) continue;
    const dir = join(downloads,entry.name);
    if (entry.isDirectory()) {
      const list = await readdir(dir, {withFileTypes:true});
      if (!list.some(item => item.name === "kubeconfig-vault" && item.isFile())) continue;
    } else if (!entry.isFile() || entry.name !== "kubeconfig-vault") continue;
    const candidate = entry.isDirectory() ? join(dir,"kubeconfig-vault") : dir;
    if (hash(await readFile(candidate)) === expected) return candidate;
  }
}

async function observe() {
  await browserDownload();
  // Only the official verification command receives the runner's GitHub environment.
  if (run("gh", ["release","verify-asset",tag,archive,"-R",repository], {env:process.env,timeout:60000}).status !== 0)
    throw new Error("The browser download failed GitHub release-asset verification");
  const original = run("/usr/bin/tar", ["-xOf",archive,"kube-unlock-age"], {encoding:null, maxBuffer:128*1024*1024});
  if (original.status !== 0 || !original.stdout.length) throw new Error("Could not verify the executable in the archive");
  const expected = hash(original.stdout);
  const archiveMarked = marked(archive);
  console.log(`Browser download ${tag} darwin-${cpu}: verified; archive quarantine=${archiveMarked}`);
  const open = run("/usr/bin/open", ["-a","Archive Utility",archive]);
  if (open.status !== 0) return "INCONCLUSIVE — the hosted desktop could not open Archive Utility";
  const deadline = Date.now() + 45000;
  let binary;
  while (Date.now() < deadline && !binary) { binary = await expandedBinary(expected); if (!binary) await delay(350); }
  if (!binary) return "INCONCLUSIVE — Archive Utility did not produce the verified executable in Downloads";
  const binaryMarked = marked(binary);
  const enabled = run("/usr/sbin/spctl", ["--status"]).stdout?.trim() || "unreported";
  console.log(`Before first launch: binary quarantine=${binaryMarked}; Gatekeeper status=${enabled}`);
  const first = run(binary, ["--version"]);
  let outcome;
  if (first.status === 0) {
    if (first.stdout.trim() !== "kubeconfig-vault " + tag) throw new Error("Unexpected version from verified first launch");
    outcome = "VERSION VERIFIED — the first invocation of this extracted copy reported its release version";
  } else if (first.error) {
    outcome = "LAUNCH INCOMPLETE — " + (first.error.code || "process could not run");
  } else outcome = `LAUNCH INCOMPLETE — exit=${first.status}, signal=${first.signal}`;
  const assessment = run("/usr/sbin/spctl", ["--assess","--type","execute",binary]);
  console.log(`Subsequent system assessment exit=${assessment.status}, signal=${assessment.signal}.`);
  if (!binaryMarked || enabled !== "assessments enabled") console.log("Normal Gatekeeper first-launch enforcement remains unverified.");
  return outcome;
}

try { console.log("Hosted observation:", await observe()); }
finally { await rm(root, {recursive:true, force:true, maxRetries:4}); }
