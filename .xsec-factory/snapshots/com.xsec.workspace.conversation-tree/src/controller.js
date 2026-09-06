import { DEFAULT_SCALE } from "./core.js";
import { canReadTree, isHiddenContext, parseContext, parseMountContext, sourceState } from "./context.js";
import {
  canStartNavigation,
  canStartRead,
  contextRevision,
  contextFailurePatch,
  errorMessage,
  initialControllerState,
  isRequestCurrent,
  readResponsePatch,
  requestAuthorityRevision,
  treeViewRevision,
  validateNavigationTree,
} from "./controller-state.js";
import { ConversationTreeInteractions } from "./interactions.js";
import { graphModel, selectedModel } from "./model.js";
import { createShell } from "./shell.js";
import { installStyles } from "./styles.js";
import { renderFatal, renderView } from "./view.js";

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

export class ConversationTreeController {
  constructor(host, requests = {}) {
    this.host = host;
    this.onRead = requests.readTree ?? null;
    this.onNavigate = requests.navigateTree ?? null;
    this.root = null;
    this.controls = null;
    this.state = null;
    this.disposed = false;
    this.lastContextRevision = null;
    this.hostContext = undefined;
    this.snapshot = undefined;
    this.themeSubscription = null;
    this.interactions = new ConversationTreeInteractions(this);
    this.actions = {
      load: () => void this.load(),
      navigate: (entryId) => void this.navigate(entryId),
      ...this.interactions.actions(),
    };
  }

  render() {
    if (!this.controls) return null;
    try {
      const graph = graphModel(this.state);
      this.state.selectedId = graph?.selectedId ?? null;
      const selected = selectedModel(this.state, graph);
      renderView({ controls: this.controls, state: this.state, graph, selected, actions: this.actions });
      return graph;
    } catch (value) {
      this.state.error = `渲染对话树失败：${errorMessage(value)}`;
      renderFatal(this.controls, this.state.error);
      return null;
    }
  }

  contextWithSnapshot(value) {
    if (this.snapshot === undefined || !isRecord(value)) return value;
    if (value.workspace !== undefined && !isRecord(value.workspace)) return value;
    return {
      ...value,
      workspace: { ...(value.workspace ?? {}), session: this.snapshot?.session ?? null },
    };
  }

  updateContext(value) {
    this.hostContext = value;
    this.applyContext(this.contextWithSnapshot(value));
  }

  updateSnapshot(snapshot) {
    this.snapshot = snapshot;
    if (this.state) this.applyContext(this.contextWithSnapshot(this.hostContext));
  }

  snapshotFailed(value) {
    this.snapshot = null;
    if (!this.state) return;
    this.applyContext(this.contextWithSnapshot(this.hostContext));
    this.state.error = `读取对话树数据失败：${errorMessage(value)}`;
    this.render();
  }

  applyContext(value) {
    const revision = contextRevision(value);
    if (revision === this.lastContextRevision) return;
    this.lastContextRevision = revision;
    if (isHiddenContext(value)) {
      this.suspend(value);
      return;
    }
    const next = this.parseUpdatedContext(value);
    if (!next) return;
    const currentId = this.state.context.sessionId ?? this.state.tree?.sessionId;
    const nextId = next.sessionId ?? next.tree?.sessionId;
    const changed = nextId !== currentId && (!next.truncated || Boolean(nextId));
    const previousViewRevision = treeViewRevision(this.state.tree);
    const requestStale = requestAuthorityRevision(this.state.context) !== requestAuthorityRevision(next);
    if (requestStale) this.state.generation += 1;
    this.state.context = next;
    if (requestStale) this.state.loading = false;
    if (requestStale) this.state.navigating = false;
    this.state.error = null;
    this.state.notice = null;
    if (changed) this.resetSessionState(next);
    else this.applyContextTree(next);
    const viewChanged = changed || previousViewRevision !== treeViewRevision(this.state.tree);
    this.render();
    if (viewChanged) this.interactions.resetView();
  }

  parseUpdatedContext(value) {
    try {
      return parseContext(value);
    } catch (error) {
      const drag = this.state.drag;
      this.state.generation += 1;
      Object.assign(this.state, contextFailurePatch({
        context: this.state.context,
        raw: value,
        message: errorMessage(error),
      }));
      this.releaseDrag(drag);
      this.render();
      return null;
    }
  }

  suspend(value) {
    const drag = this.state.drag;
    this.state.generation += 1;
    this.state.context = { ...this.state.context, raw: value, visible: false };
    this.state.loading = false;
    this.state.navigating = false;
    this.state.drag = null;
    this.releaseDrag(drag);
    this.render();
  }

  releaseDrag(drag) {
    if (drag && this.controls?.canvas.hasPointerCapture(drag.pointerId)) {
      this.controls.canvas.releasePointerCapture(drag.pointerId);
    }
    this.controls?.canvas.classList.remove("is-dragging");
  }

  resetSessionState(context) {
    Object.assign(this.state, {
      tree: context.tree,
      treeHash: context.treeHash,
      source: sourceState(context),
      loadedTree: false,
      navigationBaseHash: null,
      selectedId: null,
      query: "",
      mode: "all",
      showAgentMessages: false,
      view: { x: 24, y: 24, scale: DEFAULT_SCALE },
      error: null,
    });
  }

  applyContextTree(context) {
    const restoresAuthority = this.state.loadedTree
      && (!this.state.navigationBaseHash || context.treeHash !== this.state.navigationBaseHash);
    if (context.tree && (!this.state.loadedTree || restoresAuthority)) {
      Object.assign(this.state, {
        tree: context.tree,
        treeHash: context.treeHash,
        loadedTree: false,
        navigationBaseHash: null,
        error: null,
      });
    } else if (context.truncated) {
      this.state.treeHash = null;
    } else if (!context.sessionId) {
      Object.assign(this.state, {
        tree: null,
        treeHash: null,
        loadedTree: false,
        navigationBaseHash: null,
        selectedId: null,
      });
    } else if (!this.state.loadedTree) {
      this.state.tree = null;
      this.state.treeHash = null;
    }
    this.state.source = sourceState(context, this.state.loadedTree && Boolean(this.state.tree));
  }

  requestFence() {
    return { generation: ++this.state.generation, sessionId: this.state.context.sessionId };
  }

  isCurrent(fence) {
    return isRequestCurrent({ disposed: this.disposed, state: this.state, fence });
  }

  async load() {
    if (!canStartRead({
      disposed: this.disposed,
      loading: this.state.loading,
      navigating: this.state.navigating,
      readSupported: canReadTree(this.state.context),
      visible: this.state.context.visible,
    })) return;
    const navigationBaseHash = this.state.treeHash;
    const fence = this.requestFence();
    Object.assign(this.state, { loading: true, error: null, notice: null });
    console.info("conversation-tree.read.started");
    this.render();
    let replacedTree = false;
    try {
      const response = await this.onRead();
      if (!this.isCurrent(fence)) return;
      this.acceptReadResponse(response, navigationBaseHash);
      replacedTree = response.status === "ready";
      console.info("conversation-tree.read.completed", { status: response.status });
    } catch (value) {
      if (this.isCurrent(fence)) {
        console.error("conversation-tree.read.failed", { message: errorMessage(value) });
        this.state.error = `读取对话树失败：${errorMessage(value)}`;
      }
    }
    if (!this.isCurrent(fence)) return;
    this.state.loading = false;
    this.render();
    if (replacedTree) this.interactions.resetView();
  }

  acceptReadResponse(response, navigationBaseHash) {
    Object.assign(this.state, readResponsePatch(response, this.state.context.sessionId, navigationBaseHash));
    this.lastContextRevision = null;
  }

  async navigate(entryId) {
    if (!canStartNavigation({ disposed: this.disposed, loading: this.state.loading, navigating: this.state.navigating, visible: this.state.context.visible })) return;
    try {
      await this.performNavigation(entryId);
    } catch (value) {
      console.error("conversation-tree.navigate.failed", { message: errorMessage(value) });
      this.state.error = `切换分支失败：${errorMessage(value)}`;
      this.state.navigating = false;
      this.render();
    }
  }

  navigationRequest(entryId) {
    const graph = graphModel(this.state);
    const selected = selectedModel(this.state, graph);
    if (!selected || selected.selected.entryId !== entryId) {
      throw new Error("conversation_tree_navigation_selection_mismatch");
    }
    if (selected.navigationBlock) throw new Error(selected.navigationBlock);
    if (!this.state.treeHash) throw new Error("conversation_tree_missing_tree_hash");
    return { targetEntryId: entryId, expectedTreeHash: this.state.treeHash };
  }

  async performNavigation(entryId) {
    const request = this.navigationRequest(entryId);
    const fence = this.requestFence();
    Object.assign(this.state, { navigating: true, error: null });
    console.info("conversation-tree.navigate.started");
    this.render();
    let response;
    try {
      response = await this.onNavigate(request);
    } catch (error) {
      if (this.isCurrent(fence)) throw error;
      return;
    }
    if (!this.isCurrent(fence)) return;
    this.acceptNavigation(response, entryId, request.expectedTreeHash);
    console.info("conversation-tree.navigate.completed");
    this.state.navigating = false;
    this.render();
    this.interactions.resetView();
  }

  acceptNavigation(response, entryId, navigationBaseHash) {
    Object.assign(this.state, {
      tree: validateNavigationTree(response?.result, this.state.context.sessionId, entryId),
      treeHash: null,
      loadedTree: true,
      navigationBaseHash,
      source: { availability: "ready", label: "已切换" },
      notice: "分支已切换；等待宿主发布新的权威树摘要。",
      selectedId: entryId,
    });
  }

  applyTheme(theme) {
    document.documentElement.dataset.xsecTheme = theme?.["color-mode"] === "light" ? "light" : "dark";
  }

  async mount(nextRoot, initialContext) {
    this.root = nextRoot;
    installStyles();
    this.hostContext = initialContext;
    const mergedContext = this.contextWithSnapshot(initialContext);
    const context = parseMountContext(mergedContext);
    this.lastContextRevision = contextRevision(mergedContext);
    this.state = initialControllerState(context, sourceState(context));
    this.controls = createShell(this.root, this.actions);
    const mode = getComputedStyle(document.documentElement).getPropertyValue("--xsec-color-mode").trim();
    this.applyTheme({ "color-mode": mode });
    this.themeSubscription = this.host.onTheme?.((theme) => this.applyTheme(theme));
    this.render();
    if (this.state.tree) this.interactions.resetView();
    console.info("conversation-tree.mount", { treeAvailable: Boolean(this.state.tree) });
  }

  async update(nextContext) {
    if (!this.disposed) this.updateContext(nextContext);
  }

  async dispose() {
    console.debug("conversation-tree.dispose");
    this.disposed = true;
    if (this.state) this.state.generation += 1;
    this.themeSubscription?.dispose();
    this.root?.replaceChildren();
  }
}

export function createController(host, requests) {
  console.debug("conversation-tree.activate", { apiVersion: host.apiVersion });
  return new ConversationTreeController(host, requests);
}
