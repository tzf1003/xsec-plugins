import assert from "node:assert/strict";
import { test } from "node:test";
import { compactParameterLabel, extensionLabel, formatBytes, mimeLabel, parameterLabel, requestTarget, sourceLabel, statusClass } from "../src/format";
import type { TrafficSummary } from "../src/types";

const summary = {
  path: "/assets",
  query: "?kind=script",
  url: "https://example.test/assets?kind=script",
} as TrafficSummary;

test("table formatters preserve the legacy traffic labels", () => {
  assert.equal(mimeLabel("otherText"), "文本 / JSON");
  assert.equal(sourceLabel("proxy"), "代理");
  assert.equal(sourceLabel("replay"), "重放");
  assert.equal(extensionLabel(".js"), ".js");
  assert.equal(extensionLabel(null), "—");
});

test("table formatters preserve legacy sizes and request targets", () => {
  assert.equal(formatBytes(4_821), "4.7 KiB");
  assert.equal(formatBytes(187_432), "183 KiB");
  assert.equal(requestTarget(summary), "/assets?kind=script");
});

test("parameter labels distinguish missing metadata from an explicit false value", () => {
  assert.equal(compactParameterLabel(undefined), "未知");
  assert.equal(parameterLabel(undefined), "—");
  assert.equal(compactParameterLabel(false), "无参");
  assert.equal(parameterLabel(false), "无");
});

test("status styles distinguish informational responses from success", () => {
  assert.equal(statusClass(101), "status-informational");
  assert.equal(statusClass(204), "status-success");
});
