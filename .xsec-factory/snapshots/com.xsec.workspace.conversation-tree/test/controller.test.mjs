import assert from "node:assert/strict";
import test from "node:test";
import { ConversationTreeController } from "../src/controller.js";
import { canReadTree, parseContext, sourceState } from "../src/context.js";
import { contextRevision } from "../src/controller-state.js";
import { context, message, tree } from "./fixtures.mjs";

const projection = tree([message("root", { active: true })], { activeLeafId: "root" });
const unsupportedContext = {
  visible: true,
  workspace: {
    session: {
      session_id: "session-1",
      tree_capability: { snapshot: false, navigate: false },
    },
  },
};

function stateFor(parsed, overrides = {}) {
  return {
    context: parsed,
    tree: parsed.tree,
    treeHash: parsed.treeHash,
    source: sourceState(parsed),
    error: "old context error",
    notice: null,
    loading: true,
    navigating: false,
    loadedTree: false,
    navigationBaseHash: null,
    generation: 4,
    ...overrides,
  };
}

test("dispose is safe before mount completes", async () => {
  const controller = new ConversationTreeController({});
  await controller.dispose();
  assert.equal(controller.disposed, true);
});

test("navigation authority updates invalidate requests and clear recovered context errors", () => {
  const controller = new ConversationTreeController({});
  controller.state = stateFor(parseContext(context(projection)), { loading: false, navigating: true });
  const fence = { generation: 4, sessionId: "session-1" };
  controller.render = () => null;
  controller.interactions.resetView = () => {};
  controller.updateContext(context(projection, { status: "running" }));
  assert.equal(controller.state.generation, 5);
  assert.equal(controller.state.navigating, false);
  assert.equal(controller.isCurrent(fence), false);
  assert.equal(controller.state.error, null);
});

test("equivalent context updates do not rerender the conversation tree", () => {
  const initial = context(projection);
  const equivalent = {
    workspace: initial.workspace,
    visible: true,
    kind: "workspace-tool",
  };
  const controller = new ConversationTreeController({});
  controller.state = stateFor(parseContext(initial));
  controller.lastContextRevision = contextRevision(initial);
  let renders = 0;
  controller.render = () => { renders += 1; };
  controller.updateContext(equivalent);
  assert.equal(renders, 0);
});

test("failed navigation preserves the current viewport", async () => {
  const branching = tree([
    message("root", { active: true }),
    message("target", { parentId: "root" }),
  ], { activeLeafId: "root" });
  const controller = new ConversationTreeController({}, { navigateTree: async () => { throw new Error("rejected"); } });
  controller.state = stateFor(parseContext(context(branching)), {
    loading: false,
    selectedId: "target",
    mode: "all",
    showAgentMessages: false,
    query: "",
  });
  controller.render = () => null;
  let resets = 0;
  controller.interactions.resetView = () => { resets += 1; };
  await controller.navigate("target");
  assert.equal(resets, 0);
  assert.match(controller.state.error, /rejected/);
});

test("reads reset the viewport only after installing a ready tree", async () => {
  const parsed = parseContext(context(projection));
  const responses = [{ status: "busy" }, new Error("invalid response")];
  for (const response of responses) {
    const requests = { readTree: async () => {
      if (response instanceof Error) throw response;
      return response;
    } };
    const controller = new ConversationTreeController({}, requests);
    controller.state = stateFor(parsed, { loading: false });
    controller.render = () => null;
    let resets = 0;
    controller.interactions.resetView = () => { resets += 1; };
    await controller.load();
    assert.equal(resets, 0);
  }
  const ready = new ConversationTreeController({}, { readTree: async () => ({ status: "ready", tree: projection }) });
  ready.state = stateFor(parsed, { loading: false });
  ready.render = () => null;
  let readyResets = 0;
  ready.interactions.resetView = () => { readyResets += 1; };
  await ready.load();
  assert.equal(readyResets, 1);
});

test("new tree authority invalidates an in-flight request", () => {
  const controller = new ConversationTreeController({});
  controller.state = stateFor(parseContext(context(projection)));
  controller.render = () => null;
  controller.interactions.resetView = () => {};
  controller.updateContext(context(projection, { treeHash: "hash-2" }));
  assert.equal(controller.state.generation, 5);
  assert.equal(controller.state.loading, false);
});

test("valid no-tree recovery clears context errors", () => {
  const parsed = parseContext(unsupportedContext);
  const controller = new ConversationTreeController({});
  controller.state = stateFor(parsed, { loading: false });
  controller.render = () => null;
  controller.interactions.resetView = () => {};
  controller.updateContext(unsupportedContext);
  assert.equal(controller.state.error, null);
  assert.equal(controller.state.tree, null);
});

test("unsupported snapshots cannot reach the host read boundary", async () => {
  let requests = 0;
  const controller = new ConversationTreeController({}, { readTree: async () => { requests += 1; } });
  controller.state = stateFor(parseContext(unsupportedContext), { loading: false });
  controller.render = () => null;
  await controller.load();
  assert.equal(requests, 0);
});

test("an unbound workspace cannot reach the host read boundary", async () => {
  let requests = 0;
  const parsed = parseContext({ visible: true, workspace: {} });
  const controller = new ConversationTreeController({}, { readTree: async () => { requests += 1; } });
  controller.state = stateFor(parsed, { loading: false });
  controller.render = () => null;
  assert.equal(canReadTree(parsed), false);
  await controller.load();
  assert.equal(requests, 0);
});

test("an unbound workspace clears a previously loaded snapshot", () => {
  const controller = new ConversationTreeController({});
  controller.state = stateFor(parseContext(context(projection)), { loadedTree: true, loading: false });
  controller.render = () => null;
  controller.interactions.resetView = () => {};
  controller.updateContext({ visible: true, workspace: {} });
  assert.equal(controller.state.tree, null);
  assert.equal(controller.state.loadedTree, false);
});

test("a truncated session switch clears the previous session tree", () => {
  const controller = new ConversationTreeController({});
  controller.state = stateFor(parseContext(context(projection)), { loading: false, query: "session one" });
  controller.render = () => null;
  controller.interactions.resetView = () => {};
  const next = context({ ...projection, sessionId: "session-2" });
  next.truncated = true;
  delete next.workspace.session.conversation_tree;
  controller.updateContext(next);
  assert.equal(controller.state.context.sessionId, "session-2");
  assert.equal(controller.state.tree, null);
  assert.equal(controller.state.query, "");
});

test("a truncated update for the same session retains its browseable tree", () => {
  const controller = new ConversationTreeController({});
  controller.state = stateFor(parseContext(context(projection)), { loading: false });
  controller.render = () => null;
  controller.interactions.resetView = () => {};
  const next = context(projection);
  next.truncated = true;
  delete next.workspace.session.conversation_tree;
  controller.updateContext(next);
  assert.equal(controller.state.tree.sessionId, "session-1");
  assert.equal(controller.state.treeHash, null);
});

test("a loaded tree remains until the projection hash advances", () => {
  const parsed = parseContext(context(projection));
  const returned = tree([
    message("root", { active: true }),
    message("leaf", { parentId: "root", active: true }),
  ], { activeLeafId: "leaf" });
  const controller = new ConversationTreeController({});
  controller.state = stateFor(parsed, {
    tree: returned,
    treeHash: null,
    loadedTree: true,
    navigationBaseHash: "hash-1",
    loading: false,
  });
  controller.render = () => null;
  controller.interactions.resetView = () => {};
  controller.updateContext(context(projection));
  assert.equal(controller.state.tree.activeLeafId, "leaf");
  assert.equal(controller.state.loadedTree, true);
  assert.equal(controller.state.treeHash, null);
  controller.updateContext(context(projection, { treeHash: "hash-2" }));
  assert.equal(controller.state.tree.activeLeafId, "root");
  assert.equal(controller.state.loadedTree, false);
  assert.equal(controller.state.treeHash, "hash-2");
});

test("an explicit read records and retains the current projection hash", async () => {
  const cached = context(projection);
  const returned = tree([
    message("root", { active: true }),
    message("leaf", { parentId: "root", active: true }),
  ], { activeLeafId: "leaf" });
  const controller = new ConversationTreeController({}, {
    readTree: async () => ({ status: "ready", tree: returned }),
  });
  const parsed = parseContext(cached);
  controller.state = stateFor(parsed, { loading: false });
  controller.lastContextRevision = contextRevision(cached);
  controller.render = () => null;
  controller.interactions.resetView = () => {};
  await controller.load();
  controller.updateContext(cached);
  assert.equal(controller.state.tree.activeLeafId, "leaf");
  assert.equal(controller.state.loadedTree, true);
  assert.equal(controller.state.navigationBaseHash, "hash-1");
  assert.equal(controller.state.treeHash, null);
});

test("repeated authoritative context is processed after a non-ready read", async () => {
  const cached = context(projection);
  const controller = new ConversationTreeController({}, {
    readTree: async () => ({ status: "busy" }),
  });
  const parsed = parseContext(cached);
  controller.state = stateFor(parsed, { loading: false });
  controller.lastContextRevision = contextRevision(cached);
  controller.render = () => null;
  controller.interactions.resetView = () => {};
  await controller.load();
  assert.equal(controller.state.treeHash, null);
  controller.updateContext(cached);
  assert.equal(controller.state.treeHash, "hash-1");
  assert.equal(controller.state.tree.activeLeafId, "root");
});

test("navigation results wait for a new authoritative hash", () => {
  const branching = tree([
    message("root", { active: true }),
    message("target", { parentId: "root" }),
  ], { activeLeafId: "root" });
  const navigated = tree([
    message("root", { active: true }),
    message("target", { parentId: "root", active: true }),
  ], { activeLeafId: "target" });
  const controller = new ConversationTreeController({});
  controller.state = stateFor(parseContext(context(branching)), { loading: false });
  controller.render = () => null;
  controller.interactions.resetView = () => {};
  controller.acceptNavigation({ result: navigated }, "target", "hash-1");
  controller.updateContext(context(branching));
  assert.equal(controller.state.tree.activeLeafId, "target");
  assert.equal(controller.state.treeHash, null);
  controller.updateContext(context(navigated, { treeHash: "hash-2" }));
  assert.equal(controller.state.tree.activeLeafId, "target");
  assert.equal(controller.state.treeHash, "hash-2");
  assert.equal(controller.state.navigationBaseHash, null);
});

test("rebinding through an unbound workspace resets session filters", () => {
  const controller = new ConversationTreeController({});
  controller.state = stateFor(parseContext(context(projection)), {
    loading: false,
    query: "old query",
    mode: "active",
    showAgentMessages: true,
  });
  controller.render = () => null;
  controller.interactions.resetView = () => {};
  controller.updateContext({ visible: true, workspace: {} });
  controller.updateContext(context({ ...projection, sessionId: "session-2" }));
  assert.equal(controller.state.query, "");
  assert.equal(controller.state.mode, "all");
  assert.equal(controller.state.showAgentMessages, false);
});
