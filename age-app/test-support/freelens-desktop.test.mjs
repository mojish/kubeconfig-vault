import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { displayNamespace } from "./freelens-desktop.mjs";

for (const [silentMethod, stage, completed] of [
  ["Target.getTargets", "opening the desktop", "desktop spawned"],
  ["Runtime.evaluate", "loading the catalog", "renderer attached"],
]) {
  test(`desktop diagnostics when ${silentMethod} stalls`, async t => {
    const root = await mkdtemp(join(tmpdir(), "kcv-stalled-"));
    t.after(() => rm(root, {recursive:true, force:true}));
    const binary = join(root, "silent-desktop");
    // The real driver talks to this fixture over the same inherited CDP pipes
    // as Electron. Reply only far enough to reach the selected failure.
    await writeFile(binary, `#!/usr/bin/env node
const fs = require("node:fs");
const input = fs.createReadStream(null, {fd:3, encoding:"utf8"});
const replies = {
  "Target.getTargets": {targetInfos:[{type:"page", url:"about:blank", targetId:"fixture"}]},
  "Target.attachToTarget": {sessionId:"private-session-marker"},
  "Page.getFrameTree": {frameTree:{frame:{id:"fixture"}}},
};
let buffer = "";
input.on("data", chunk => {
  buffer += chunk;
  let end;
  while ((end = buffer.indexOf("\\0")) !== -1) {
    const {id, method} = JSON.parse(buffer.slice(0, end));
    buffer = buffer.slice(end + 1);
    if (method !== ${JSON.stringify(silentMethod)}) {
      fs.writeSync(4, JSON.stringify({id, result:replies[method]}) + "\\0");
    }
  }
});\n`, {mode:0o700});
    const viewTimeoutMs = 3000;
    await assert.rejects(displayNamespace({
      binary, root, kubeconfig:join(root, "fixture-config"), context:"private-context-marker",
      namespace:"private-namespace-marker", received:() => false,
      signal:new AbortController().signal, kubectlConnected:true, viewTimeoutMs,
    }), error => {
      assert.ok(error.message.includes(`stopped while ${stage} (last completed: ${completed},`), error.message);
      assert.ok(error.message.includes(`unanswered method: ${silentMethod},`), error.message);
      assert.match(error.message, /child: running, prior kubectl request: passed/);
      assert.ok(Number(/elapsed: (\d+) ms/.exec(error.message)[1]) >= viewTimeoutMs - 1);
      assert.doesNotMatch(error.message + error.cause.message, /private-|about:blank|fixture-config/);
      return true;
    });
  });
}
