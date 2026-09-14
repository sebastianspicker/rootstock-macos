/** Cached graph ordering and a bounded, keyboard-accessible sidebar page. */
import { element } from "./runtime";
import type { Controller } from "./runtime";
import type { GraphModel, ViewerNode } from "./types";
import { nodeListItem } from "./view";

export const NODE_PAGE_SIZE = 200;
const orderings = new WeakMap<GraphModel, ViewerNode[]>();

export function orderedNodes(graph: GraphModel): ViewerNode[] {
  let nodes = orderings.get(graph);
  if (!nodes) {
    nodes = [...graph.nodes].sort((a, b) => (a.label ?? a.id).localeCompare(b.label ?? b.id));
    orderings.set(graph, nodes);
  }
  return nodes;
}

type ListState = {
  graph: GraphModel;
  visible: ViewerNode[];
  page: number;
  renderedPage: number;
  controls: HTMLElement;
  range: HTMLElement;
  previous: HTMLButtonElement;
  next: HTMLButtonElement;
};
const lists = new WeakMap<Controller, ListState>();

function listState(controller: Controller): ListState {
  let state = lists.get(controller);
  if (state) return state;
  const previous = element("button", { type: "button", text: "Previous" });
  const next = element("button", { type: "button", text: "Next" });
  const range = element("span", { "aria-live": "polite", "aria-atomic": "true" });
  const controls = element("nav", { class: "node-pagination", "aria-label": "Node pages" }, [
    previous,
    range,
    next,
  ]);
  controller.dom.nodeList.before(controls);
  state = {
    graph: controller.state.graph,
    visible: [],
    page: 0,
    renderedPage: -1,
    controls,
    range,
    previous,
    next,
  };
  lists.set(controller, state);
  previous.addEventListener("click", () => changePage(controller, -1));
  next.addEventListener("click", () => changePage(controller, 1));
  return state;
}

function changePage(controller: Controller, delta: number): void {
  const state = listState(controller);
  state.page = Math.max(
    0,
    Math.min(Math.ceil(state.visible.length / NODE_PAGE_SIZE) - 1, state.page + delta),
  );
  renderPage(controller, state);
}

export function resetNodeList(controller: Controller): void {
  const state = listState(controller);
  state.graph = controller.state.graph;
  state.visible = orderedNodes(state.graph).filter((node) =>
    controller.state.render.visibleNodeIds.has(node.id),
  );
  state.page = 0;
  state.renderedPage = -1;
  renderPage(controller, state);
}

export function renderNodeList(controller: Controller): void {
  const state = listState(controller);
  if (state.graph !== controller.state.graph || state.renderedPage < 0) {
    resetNodeList(controller);
    return;
  }
  const selected = controller.state.selection.selectedId;
  const index = state.visible.findIndex((node) => node.id === selected);
  if (index >= 0) state.page = Math.floor(index / NODE_PAGE_SIZE);
  renderPage(controller, state);
}

function renderPage(controller: Controller, state: ListState): void {
  const start = state.page * NODE_PAGE_SIZE;
  const end = Math.min(start + NODE_PAGE_SIZE, state.visible.length);
  if (state.renderedPage !== state.page) {
    controller.dom.nodeList.replaceChildren(
      ...state.visible.slice(start, end).map((node) => nodeListItem(controller, node)),
    );
    state.renderedPage = state.page;
  }
  for (const button of controller.dom.nodeList.querySelectorAll("button[data-node-id]"))
    button.setAttribute(
      "aria-current",
      String(button.getAttribute("data-node-id") === controller.state.selection.selectedId),
    );
  controller.dom.nodeListCount.textContent = String(state.visible.length);
  controller.dom.nodeListEmpty.hidden = state.visible.length > 0;
  state.range.textContent = `${state.visible.length ? start + 1 : 0}–${end} of ${state.visible.length}`;
  state.previous.disabled = state.page === 0;
  state.next.disabled = end >= state.visible.length;
}
