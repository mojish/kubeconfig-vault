import { once } from "node:events";

// A child may exit before its stdout and stderr pipes deliver their last bytes.
export function captureProcess(child) {
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8").on("data", chunk => { stdout += chunk; });
  child.stderr.setEncoding("utf8").on("data", chunk => { stderr += chunk; });
  const operation = {child, done: false, get output() { return stdout; }};
  operation.promise = once(child, "close").then(([code]) => {
    Object.assign(operation, {code, stdout, stderr, done: true});
    return operation;
  });
  return operation;
}
