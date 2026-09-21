import assert from "node:assert/strict";
import { test } from "node:test";
import { shouldClearNewTraffic, showTrafficEmpty, workbenchNotice } from "../src/traffic/workbench-state";

test("new-traffic notice survives older cursor pages and clears on the latest page", () => {
  assert.equal(shouldClearNewTraffic(undefined), true);
  assert.equal(shouldClearNewTraffic("cursor-page-2"), false);
});

test("list refreshes keep action errors and only replace list-owned failures", () => {
  assert.equal(workbenchNotice("打开流量工具失败：denied", null), "打开流量工具失败：denied");
  assert.equal(workbenchNotice("引用流量失败：stale", null), "引用流量失败：stale");
  assert.equal(workbenchNotice("打开流量工具失败：denied", "读取抓包流量失败：timeout"), "读取抓包流量失败：timeout");
  assert.equal(workbenchNotice(null, null), null);
});

test("empty state stays hidden while settings or list errors are visible", () => {
  assert.equal(showTrafficEmpty(null, null, 0), true);
  assert.equal(showTrafficEmpty("读取默认筛选失败：offline", null, 0), false);
  assert.equal(showTrafficEmpty(null, "读取抓包流量失败：timeout", 0), false);
  assert.equal(showTrafficEmpty("打开流量工具失败：denied", null, 0), false);
  assert.equal(showTrafficEmpty(null, null, 1), false);
});
