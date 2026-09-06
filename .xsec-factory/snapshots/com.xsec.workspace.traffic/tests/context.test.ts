import assert from "node:assert/strict";
import { test } from "node:test";
import { parseContext } from "../src/context";

test("workspace traffic context uses the display revision and excludes session payload", () => {
  const context = parseContext({
    kind: "workspace-tool",
    surface: { bindingRevision: "surface-v1-traffic" },
    tool: { id: "traffic", kind: "traffic", title: "抓包流量" },
    workspace: {
      mode: "interactive",
      dock: "side",
      canAddComposerReference: true,
      session: { session_id: "session-private", transcript: "x".repeat(70 * 1024) },
    },
  });

  assert.equal(context.kind, "workspace-tool");
  assert.equal(context.surface.bindingRevision, "surface-v1-traffic");
  assert.deepEqual(context.workspace, {
    mode: "interactive",
    dock: "side",
    canAddComposerReference: true,
  });
});

test("workspace traffic context requires a host-owned display revision", () => {
  assert.throws(() => parseContext({
    kind: "workspace-tool",
    tool: { id: "traffic", kind: "traffic", title: "抓包流量" },
    workspace: { mode: "interactive", dock: "side" },
  }), /工作区表面无效/);
});
