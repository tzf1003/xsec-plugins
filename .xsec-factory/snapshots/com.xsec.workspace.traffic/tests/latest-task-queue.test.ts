import assert from "node:assert/strict";
import { test } from "node:test";
import { LatestTaskQueue } from "../src/latest-task-queue";

/** Create a promise whose completion the queue test controls explicitly. */
function deferred() {
  let resolve = () => {};
  const promise = new Promise<void>((accept) => { resolve = accept; });
  return { promise, resolve };
}

test("latest task queue serializes requests and retains one trailing refresh", async () => {
  const first = deferred();
  const completed = deferred();
  const started: number[] = [];
  let active = 0; let maximumActive = 0;
  const task = (id: number, wait?: Promise<void>, finish = false) => async () => {
    started.push(id); active += 1; maximumActive = Math.max(maximumActive, active);
    if (wait) await wait;
    active -= 1;
    if (finish) completed.resolve();
  };
  const queue = new LatestTaskQueue();
  queue.schedule(task(1, first.promise));
  queue.schedule(task(2));
  queue.schedule(task(3, undefined, true));
  assert.deepEqual(started, [1]);
  first.resolve();
  await completed.promise;
  assert.deepEqual(started, [1, 3]);
  assert.equal(maximumActive, 1);
});
