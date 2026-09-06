import assert from "node:assert/strict";
import test from "node:test";
import {
  activeLeafId,
  activePath,
  focusPath,
  layoutTree,
  matchesQuery,
  nodeDepths,
  panView,
  parentMap,
  preferredSelection,
  validateTree,
  visibleMessages,
  zoomView,
} from "../src/index.js";
import { message, tree } from "./fixtures.mjs";

const branch = [
  message("root", { timestamp: 1, active: true }),
  message("agent-a", { parentId: "root", role: "assistant", timestamp: 2, active: true }),
  message("user-a", { parentId: "agent-a", timestamp: 3, active: true }),
  message("user-b", { parentId: "agent-a", timestamp: 4 }),
];

test("layout is deterministic and keeps the historical card geometry", () => {
  const first = layoutTree(branch);
  const second = layoutTree(branch);
  assert.deepEqual([...first.positions], [...second.positions]);
  assert.deepEqual(first.positions.get("root"), { x: 140, y: 40 });
  assert.equal(first.positions.get("user-a").y, 240);
  assert.equal(first.positions.get("user-b").x - first.positions.get("user-a").x, 200);
});

test("active leaf falls back to the last active message", () => {
  assert.equal(activeLeafId(branch, null), "user-a");
  assert.equal(activeLeafId(branch, "user-b"), "user-b");
});

test("active path follows exact parent ancestry", () => {
  assert.deepEqual(activePath(branch, "user-a").map((item) => item.entryId), ["root", "agent-a", "user-a"]);
});

test("a stable branch group connects a projected message parent", () => {
  const rows = [message("root"), message("child", { parentId: "provider-entry", branchGroupId: "root" })];
  assert.equal(parentMap(rows).get("child"), "root");
});

test("missing parents and cycles fail fast", () => {
  assert.throws(() => parentMap([message("child", { parentId: "missing" })]), /parent_missing/);
  assert.throws(() => parentMap([
    message("left", { parentId: "right" }),
    message("right", { parentId: "left" }),
  ]), /conversation_tree_cycle/);
  assert.throws(() => parentMap([message("same"), message("same")]), /duplicate_id/);
});

test("node depths are precomputed once for long conversations", () => {
  const rows = Array.from({ length: 1000 }, (_, index) => message(`node-${index}`, {
    parentId: index ? `node-${index - 1}` : null,
  }));
  const depths = nodeDepths(rows);
  assert.equal(depths.get("node-0"), 1);
  assert.equal(depths.get("node-999"), 1000);
});

test("layout handles deep conversation chains without recursive stack growth", () => {
  const rows = Array.from({ length: 5000 }, (_, index) => message(`node-${index}`, {
    parentId: index ? `node-${index - 1}` : null,
  }));
  const layout = layoutTree(rows);
  assert.equal(layout.positions.size, 5000);
  assert.deepEqual(layout.positions.get("node-0"), { x: 40, y: 40 });
  assert.deepEqual(layout.positions.get("node-4999"), { x: 40, y: 499940 });
});

test("Agent nodes are hidden by default while user ancestry stays connected", () => {
  const visible = visibleMessages(branch, false);
  assert.deepEqual(visible.map((item) => item.entryId), ["root", "user-a", "user-b"]);
  assert.equal(visible.find((item) => item.entryId === "user-a").parentId, "root");
  assert.equal(visibleMessages(branch, true).length, branch.length);
  assert.equal(preferredSelection(branch, visible, "agent-a"), "root");
});

test("search matches text and thought without removing nodes", () => {
  const row = message("search", { text: "资产发现", thought: "Inspect headers" });
  assert.equal(matchesQuery(row, "资产"), true);
  assert.equal(matchesQuery(row, "headers"), true);
  assert.equal(matchesQuery(row, "missing"), false);
});

test("viewport pan, zoom and active-path reset remain bounded", () => {
  assert.deepEqual(panView({ x: 10, y: 20, scale: 1 }, 3, -2), { x: 7, y: 22, scale: 1 });
  assert.deepEqual(zoomView({ x: 0, y: 0, scale: 1 }, 2, { x: 50, y: 50 }), { x: -30, y: -30, scale: 1.6 });
  const focused = focusPath({ width: 420, height: 340 }, { x: 100, y: 240 }, [{ x: 100, y: 40 }, { x: 100, y: 240 }]);
  assert.equal(focused.scale, 0.85);
  assert.equal(Math.round(focused.y * 10) / 10, 25.9);
  const bent = focusPath({ width: 640, height: 340 }, { x: 400, y: 240 }, [{ x: 40, y: 40 }, { x: 400, y: 240 }]);
  const left = bent.x + 40 * bent.scale;
  const right = 640 - (bent.x + (400 + 166) * bent.scale);
  assert.ok(Math.abs(left - right) < 0.2);
});

test("tree validation requires a real session and active leaf", () => {
  assert.throws(() => validateTree(tree(branch, { sessionId: "" })), /invalid_session_id/);
  assert.throws(() => validateTree(tree(branch, { activeLeafId: "missing" })), /active_leaf_missing/);
  assert.throws(() => validateTree({ ...tree(branch), protocolVersion: 2 }), /unsupported_protocol/);
  assert.throws(() => validateTree({ ...tree(branch), protocolVersion: undefined }), /unsupported_protocol/);
});
