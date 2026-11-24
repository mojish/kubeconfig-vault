import { once } from "node:events";

// A child may exit before its stdout and stderr pipes deliver their last bytes.
export function captureProcess(child, maxChars = Infinity) {
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8").on("data", chunk => { stdout = (stdout + chunk).slice(-maxChars); });
  child.stderr.setEncoding("utf8").on("data", chunk => { stderr = (stderr + chunk).slice(-maxChars); });
  const operation = {child, done: false, get output() { return stdout; }};
  operation.promise = once(child, "close").then(([code]) => {
    Object.assign(operation, {code, stdout, stderr, done: true});
    return operation;
  });
  return operation;
}
