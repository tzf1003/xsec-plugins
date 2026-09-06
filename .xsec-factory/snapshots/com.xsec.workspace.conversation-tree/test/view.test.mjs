import assert from "node:assert/strict";
import test from "node:test";
import { emptyContent } from "../src/view.js";

const state = {
  loading: false,
  source: { availability: "ready" },
  context: { session: null },
};

test("empty tree and filtered tree expose explicit empty states", () => {
  assert.match(emptyContent(state, { messages: [], visible: [] })[0], /没有消息节点/);
  assert.match(emptyContent(state, { messages: [{}], visible: [] })[0], /没有可见节点/);
});

test("unbound workspaces expose a no-session state", () => {
  const unbound = { ...state, source: { availability: "missing_session" } };
  const [title, , canLoad] = emptyContent(unbound, null);
  assert.match(title, /未绑定会话/);
  assert.equal(canLoad, false);
});
