import assert from "node:assert/strict";
import test from "node:test";
import {
  resolveRefreshAfterLoad,
  resolveRefreshRetryTimerPolicy,
  shouldRefreshForContext,
  startImmediateRefresh,
} from "../com.xsec.desktop/frontend/index.js";

const MAX = 3;
const BASE = 750;

test("idle refresh failure schedules first bounded retry and keeps dirty intent", () => {
  const plan = resolveRefreshAfterLoad({
    succeeded: false,
    refreshQueued: false,
    refreshDirty: true,
    refreshRetryAttempt: 0,
    maxRetries: MAX,
    retryBaseMs: BASE,
  });
  assert.equal(plan.action, "schedule-retry");
  assert.equal(plan.refreshDirty, true);
  assert.equal(plan.refreshQueued, false);
  assert.equal(plan.refreshRetryAttempt, 1);
  assert.equal(plan.delay, BASE);
});

test("consecutive retry failures without new resource updates keep scheduling until cap", () => {
  let state = {
    refreshQueued: false,
    refreshDirty: true,
    refreshRetryAttempt: 0,
  };

  for (let expectedAttempt = 1; expectedAttempt <= MAX; expectedAttempt += 1) {
    const plan = resolveRefreshAfterLoad({
      succeeded: false,
      ...state,
      maxRetries: MAX,
      retryBaseMs: BASE,
    });
    assert.equal(plan.action, "schedule-retry");
    assert.equal(plan.refreshDirty, true);
    assert.equal(plan.refreshRetryAttempt, expectedAttempt);
    assert.equal(plan.delay, BASE * (2 ** (expectedAttempt - 1)));
    state = {
      refreshQueued: plan.refreshQueued,
      refreshDirty: plan.refreshDirty,
      refreshRetryAttempt: plan.refreshRetryAttempt,
    };
  }

  const giveUp = resolveRefreshAfterLoad({
    succeeded: false,
    ...state,
    maxRetries: MAX,
    retryBaseMs: BASE,
  });
  assert.equal(giveUp.action, "give-up");
  assert.equal(giveUp.refreshDirty, false);
  assert.equal(giveUp.refreshRetryAttempt, 0);
});

test("mid-flight queued failure schedules retry instead of dropping dirty intent", () => {
  const plan = resolveRefreshAfterLoad({
    succeeded: false,
    refreshQueued: true,
    refreshDirty: false,
    refreshRetryAttempt: 0,
    maxRetries: MAX,
    retryBaseMs: BASE,
  });
  assert.equal(plan.action, "schedule-retry");
  assert.equal(plan.refreshDirty, true);
  assert.equal(plan.refreshQueued, false);
});

test("success clears dirty intent; queued success reloads with dirty retained", () => {
  const idle = resolveRefreshAfterLoad({
    succeeded: true,
    refreshQueued: false,
    refreshDirty: true,
    refreshRetryAttempt: 2,
  });
  assert.equal(idle.action, "idle");
  assert.equal(idle.refreshDirty, false);
  assert.equal(idle.refreshRetryAttempt, 0);

  const reload = resolveRefreshAfterLoad({
    succeeded: true,
    refreshQueued: true,
    refreshDirty: true,
    refreshRetryAttempt: 2,
  });
  assert.equal(reload.action, "reload");
  assert.equal(reload.refreshDirty, true);
  assert.equal(reload.refreshRetryAttempt, 0);
});

test("timer policy: disposed is a noop", () => {
  assert.deepEqual(
    resolveRefreshRetryTimerPolicy({ disposed: true, mode: "schedule" }),
    { clearPending: false, armTimer: false },
  );
  assert.deepEqual(
    resolveRefreshRetryTimerPolicy({ disposed: true, mode: "immediate-load" }),
    { clearPending: false, armTimer: false },
  );
});

test("timer policy: newer schedule always replaces pending timer", () => {
  const policy = resolveRefreshRetryTimerPolicy({ disposed: false, mode: "schedule" });
  assert.equal(policy.clearPending, true);
  assert.equal(policy.armTimer, true);
});

test("timer policy: immediate load clears pending retry without arming", () => {
  const policy = resolveRefreshRetryTimerPolicy({ disposed: false, mode: "immediate-load" });
  assert.equal(policy.clearPending, true);
  assert.equal(policy.armTimer, false);
});

test("pending retry interrupted by resource update then failed load replaces old delay", () => {
  // Simulate: first failure armed attempt=1 delay=BASE (pending timer).
  let state = {
    refreshQueued: false,
    refreshDirty: true,
    refreshRetryAttempt: 0,
  };
  const first = resolveRefreshAfterLoad({
    succeeded: false,
    ...state,
    maxRetries: MAX,
    retryBaseMs: BASE,
  });
  assert.equal(first.action, "schedule-retry");
  assert.equal(first.delay, BASE);
  state = {
    refreshQueued: first.refreshQueued,
    refreshDirty: first.refreshDirty,
    refreshRetryAttempt: first.refreshRetryAttempt,
  };

  // Resource update / manual refresh starts an immediate load: supersede pending timer.
  const interrupt = resolveRefreshRetryTimerPolicy({ disposed: false, mode: "immediate-load" });
  assert.equal(interrupt.clearPending, true, "must clear old pending retry timer");
  assert.equal(interrupt.armTimer, false);

  // That interrupting load fails: schedule with the next exponential delay.
  const afterFail = resolveRefreshAfterLoad({
    succeeded: false,
    refreshQueued: false,
    refreshDirty: true,
    refreshRetryAttempt: state.refreshRetryAttempt,
    maxRetries: MAX,
    retryBaseMs: BASE,
  });
  assert.equal(afterFail.action, "schedule-retry");
  assert.equal(afterFail.refreshRetryAttempt, 2);
  assert.equal(afterFail.delay, BASE * 2);

  // Newer schedule must replace (not keep) the old timer.
  const replace = resolveRefreshRetryTimerPolicy({ disposed: false, mode: "schedule" });
  assert.equal(replace.clearPending, true, "must clear stale pending timer before re-arm");
  assert.equal(replace.armTimer, true, "must arm timer with newly calculated delay");
});

test("immediate resource refresh cancels a pending retry before loading", async () => {
  let retryFired = false;
  let loadStarted = false;
  const pendingRetry = setTimeout(() => {
    retryFired = true;
  }, 5);

  startImmediateRefresh({
    disposed: false,
    clearPending: () => clearTimeout(pendingRetry),
    startLoad: () => {
      loadStarted = true;
    },
  });
  await new Promise((resolve) => setTimeout(resolve, 15));

  assert.equal(loadStarted, true);
  assert.equal(retryFired, false);
});

test("context refresh runs only for assignment or visibility transitions", () => {
  assert.equal(shouldRefreshForContext({
    visible: true,
    assignmentChanged: true,
    becameVisible: false,
  }), true);
  assert.equal(shouldRefreshForContext({
    visible: true,
    assignmentChanged: false,
    becameVisible: true,
  }), true);
  assert.equal(shouldRefreshForContext({
    visible: true,
    assignmentChanged: false,
    becameVisible: false,
  }), false);
  assert.equal(shouldRefreshForContext({
    visible: false,
    assignmentChanged: true,
    becameVisible: false,
  }), false);
});
