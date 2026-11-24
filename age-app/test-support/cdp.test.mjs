import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { test } from "node:test";
import { devtoolsPipe } from "./cdp.mjs";

test("slow commands can finish within a shared navigation deadline", async t => {
  t.mock.timers.enable({apis:["setTimeout"]});
  const child = new EventEmitter();
  child.stdio = [null, null, null, new PassThrough(), new PassThrough()];
  let remainingMs = 85_000;
  const {call} = devtoolsPipe(child, {getTimeoutMs:() => remainingMs});

  const startup = call("Target.getTargets");
  t.mock.timers.tick(18_000);
  child.stdio[4].write(JSON.stringify({id:1, result:{targetInfos:[]}}) + "\0");
  assert.deepEqual(await startup, {targetInfos:[]});

  remainingMs -= 18_000;
  const timeout = assert.rejects(call("Page.getFrameTree", {marker:"fixture parameter"}),
    {message:"Browser debugging command Page.getFrameTree timed out after 67000 ms"});
  t.mock.timers.tick(remainingMs);
  await timeout;
});
