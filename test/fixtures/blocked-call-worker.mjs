// Blocks a runtime worker on a callback that never settles, then waits to be terminated.
import { createRequire } from "node:module";
import { parentPort } from "node:worker_threads";

const native = createRequire(import.meta.url)("../../native/index.cjs");
// Referenced for the worker's lifetime: a garbage collection would end the wait for a pending
// Promise that nothing references, and with it the blocked call.
const never = new Promise(() => {});

native.testing
  .syncCall(
    () => {
      parentPort.postMessage("called");
      return never;
    },
    1,
    1_500,
  )
  .catch(() => {});
