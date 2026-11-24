import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { test } from "node:test";
import { captureProcess } from "./captured-process.mjs";

test("captured commands finish after draining both pipes", async () => {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  const operation = captureProcess(child);
  child.stdout.write("visible prompt");
  assert.equal(operation.output, "visible prompt");
  child.emit("exit", 1, null);
  await Promise.resolve();
  assert.equal(operation.done, false);
  child.stdout.end(" done");
  child.stderr.end("late diagnostic");
  child.emit("close", 1, null);
  const result = await operation.promise;
  assert.equal(result.code, 1);
  assert.equal(result.stdout, "visible prompt done");
  assert.equal(result.stderr, "late diagnostic");
});
