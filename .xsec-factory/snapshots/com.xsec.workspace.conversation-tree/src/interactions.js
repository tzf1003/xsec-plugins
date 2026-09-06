import { focusPath, panView, zoomView } from "./core.js";
import { graphModel, orderedNodeIds } from "./model.js";
import { applyTransform } from "./view.js";

const WHEEL_LINE_PIXELS = 16;
const ZOOM_STEP = 0.08;

export class ConversationTreeInteractions {
  constructor(runtime) {
    this.runtime = runtime;
  }

  actions() {
    return {
      query: (value) => this.query(value),
      mode: (value) => this.mode(value),
      agents: (value) => this.agents(value),
      select: (entryId) => this.select(entryId),
      key: (event, entryId) => this.key(event, entryId),
      context: () => this.toggleContext(),
      zoom: (delta) => this.zoom(delta),
      reset: () => this.resetView(),
      pointerDown: (event) => this.pointerDown(event),
      pointerMove: (event) => this.pointerMove(event),
      pointerUp: (event) => this.pointerUp(event),
      wheel: (event) => this.wheel(event),
    };
  }

  query(value) {
    this.runtime.state.query = value;
    this.runtime.render();
  }

  mode(value) {
    const state = this.runtime.state;
    state.mode = value;
    if (value === "active") state.selectedId = graphModel(state)?.leafId;
    this.runtime.render();
    this.resetView();
  }

  agents(value) {
    this.runtime.state.showAgentMessages = value;
    this.runtime.render();
    this.resetView();
  }

  toggleContext() {
    this.runtime.state.contextExpanded = !this.runtime.state.contextExpanded;
    this.runtime.render();
  }

  resetView() {
    const { state, controls } = this.runtime;
    const graph = graphModel(state);
    if (!graph?.positioned.length || !controls) return;
    const anchor = graph.positions.get(graph.leafId) ?? graph.positions.get(graph.selectedId) ?? graph.positioned[0];
    const points = graph.active.flatMap((message) => {
      const point = graph.positions.get(message.entryId);
      return point ? [{ x: point.x, y: point.y }] : [];
    });
    const rect = controls.canvas.getBoundingClientRect();
    state.view = focusPath({ width: rect.width, height: rect.height }, anchor, points);
    applyTransform(controls, state);
  }

  zoom(delta, origin) {
    const { state, controls } = this.runtime;
    if (!controls || !state.tree || !state.context.visible) return;
    const rect = controls.canvas.getBoundingClientRect();
    const focus = origin ?? { x: rect.width / 2, y: rect.height / 2 };
    state.view = zoomView(state.view, state.view.scale + delta, focus);
    applyTransform(controls, state);
  }

  select(entryId, focus = false) {
    const { state, controls } = this.runtime;
    state.selectedId = entryId;
    this.runtime.render();
    if (focus) controls?.stage.querySelector(`[data-entry-id="${CSS.escape(entryId)}"]`)?.focus();
  }

  key(event, entryId) {
    const graph = graphModel(this.runtime.state);
    if (!graph) return;
    const ids = orderedNodeIds(graph);
    const index = ids.indexOf(entryId);
    const offsets = { ArrowLeft: -1, ArrowUp: -1, ArrowRight: 1, ArrowDown: 1 };
    let next = offsets[event.key] === undefined ? null : ids[index + offsets[event.key]];
    if (event.key === "Home") next = ids[0];
    if (event.key === "End") next = ids.at(-1);
    if (!next) return;
    event.preventDefault();
    this.select(next, true);
  }

  pointerDown(event) {
    const { state, controls } = this.runtime;
    if (event.button !== 0 || !state.context.visible) return;
    if (event.target.closest(".ct-node,[data-tree-control],button,input")) return;
    event.currentTarget.setPointerCapture(event.pointerId);
    state.drag = { pointerId: event.pointerId, x: event.clientX, y: event.clientY, view: state.view };
    controls.canvas.classList.add("is-dragging");
  }

  pointerMove(event) {
    const { state, controls } = this.runtime;
    const drag = state.drag;
    if (!drag || drag.pointerId !== event.pointerId) return;
    state.view = { ...drag.view, x: drag.view.x + event.clientX - drag.x, y: drag.view.y + event.clientY - drag.y };
    applyTransform(controls, state);
  }

  pointerUp(event) {
    const { state, controls } = this.runtime;
    if (state.drag?.pointerId !== event.pointerId) return;
    state.drag = null;
    controls.canvas.classList.remove("is-dragging");
    if (controls.canvas.hasPointerCapture(event.pointerId)) controls.canvas.releasePointerCapture(event.pointerId);
  }

  wheel(event) {
    const { state, controls } = this.runtime;
    if (!state.tree || !state.context.visible) return;
    event.preventDefault();
    event.stopPropagation();
    const rect = controls.canvas.getBoundingClientRect();
    const unit = event.deltaMode === 1 ? WHEEL_LINE_PIXELS : event.deltaMode === 2 ? rect.height : 1;
    if (event.ctrlKey) {
      const focus = { x: event.clientX - rect.left, y: event.clientY - rect.top };
      this.zoom(event.deltaY > 0 ? -ZOOM_STEP : ZOOM_STEP, focus);
      return;
    }
    state.view = panView(state.view, event.deltaX * unit, event.deltaY * unit);
    applyTransform(controls, state);
  }
}
