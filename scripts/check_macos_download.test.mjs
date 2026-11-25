import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { test } from "node:test";
import { setImmediate } from "node:timers/promises";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";
import * as cdp from "../age-app/test-support/cdp.mjs";

test("an unanswered Mac download startup command times out and cleans up", async t => {
  const scratch = await mkdtemp(join(tmpdir(), "kcv-silent-chrome-"));
  t.after(() => rm(scratch, {recursive:true, force:true}));
  const chrome = new EventEmitter();
  chrome.stdio = [null, null, null, new PassThrough(), new PassThrough()];
  chrome.exitCode = chrome.signalCode = null;
  const sent = new Promise(resolve => chrome.stdio[3].once("data", resolve));
  chrome.kill = signal => {
    chrome.signalCode = signal;
    chrome.emit("exit", null, signal);
  };

  // Run the actual hosted entry point. Only the OS identity, temp location
  // and child processes are substitutes. Its CDP calls and file cleanup are real.
  const context = createContext({console, process:{platform:"darwin", arch:"arm64",
    argv:["node", "check_macos_download.mjs", "v0.5.1"],
    env:{RUNNER_ENVIRONMENT:"github-hosted", GITHUB_ACTIONS:"true"}}});
  const driver = new SourceTextModule(await readFile(new URL("./check_macos_download.mjs", import.meta.url), "utf8"), {context});
  const substitutes = {
    "node:child_process": {spawn:() => chrome, spawnSync:() => assert.fail("unexpected subprocess")},
    "node:os": {tmpdir:() => scratch},
    "../age-app/test-support/cdp.mjs": cdp,
  };
  await driver.link(async name => {
    const api = substitutes[name] ?? await import(name);
    return new SyntheticModule(Object.keys(api), function () {
      for (const key of Object.keys(api)) this.setExport(key, api[key]);
    }, {context});
  });

  t.mock.timers.enable({apis:["setTimeout"]});
  const finished = assert.rejects(driver.evaluate(), /did not complete Browser\.getVersion/);
  try {
    assert.equal(JSON.parse((await sent).toString().replace(/\0$/, "")).method, "Browser.getVersion");
    t.mock.timers.tick(29_999);
    await setImmediate();
    assert.equal(chrome.signalCode, null);
    t.mock.timers.tick(1);
    await setImmediate();
    assert.equal(chrome.signalCode, "SIGTERM");
  } finally {
    chrome.stdio[4].end();
    await finished;
  }
  assert.deepEqual(await readdir(scratch), []);
});
