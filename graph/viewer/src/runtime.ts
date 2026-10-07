/** Provides small DOM and display-safety primitives shared across viewer modules. */

import type { ViewerDom } from "./dom";
import type { SpatialGrid } from "./spatial";
import type {
  GraphPayload,
  NodeId,
  Theme,
  ViewerNode,
  ViewerState,
  ViewerWorkspace,
} from "./types";

export interface ViewerActions {
  applyTheme(controller: Controller, value: Theme): void;
  centerNode(controller: Controller, nodeId: NodeId): void;
  closeInspector(controller: Controller): void;
  closeResults(controller: Controller): void;
  enterFocusMode(controller: Controller, nodeId: NodeId): void;
  exitFocusMode(controller: Controller): void;
  exportPng(controller: Controller): void;
  hideContextMenu(controller: Controller): void;
  hideConnectionGate(controller: Controller): void;
  inspectNode(controller: Controller, nodeId: NodeId): void;
  markDirty(controller: Controller): void;
  replaceGraph(controller: Controller, payload: GraphPayload): void;
  resetPath(controller: Controller): void;
  resetViewport(controller: Controller): void;
  revealNode(controller: Controller, nodeId: NodeId): void;
  transitionWorkspace(controller: Controller, workspace: ViewerWorkspace, focus?: boolean): void;
  selectNode(controller: Controller, nodeId: NodeId): void;
  selectTab(controller: Controller, tab: "explore" | "queries"): void;
  setClusteredLayout(controller: Controller, enabled: boolean): void;
  setLiveStatus(controller: Controller, message: string, state?: string): void;
  showConnectionGate(controller: Controller, message?: string): void;
  togglePathMode(controller: Controller, sourceId?: NodeId | null): void;
  updateVisibility(controller: Controller): void;
  zoomViewport(controller: Controller, factor: number): void;
}

export interface Controller {
  state: ViewerState;
  dom: ViewerDom;
  spatial: SpatialGrid<ViewerNode>;
  unclusteredPositions: Map<NodeId, { x: number; y: number }> | null;
  actions: ViewerActions;
}

export function element<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attributes: Record<string, string> = {},
  children: Node[] = [],
): HTMLElementTagNameMap[K] {
  const result = document.createElement(tag);
  for (const [name, value] of Object.entries(attributes)) {
    if (name === "class") result.className = value;
    else if (name === "text") result.textContent = value;
    else result.setAttribute(name, value);
  }
  for (const child of children) result.appendChild(child);
  return result;
}

export function setPressed(button: HTMLButtonElement, pressed: boolean): void {
  button.classList.toggle("active", pressed);
  button.setAttribute("aria-pressed", String(pressed));
}

const MAX_PROPERTY_DEPTH = 4;
const MAX_PROPERTY_LENGTH = 512;
const MAX_PROPERTY_ENTRIES = 20;

/** Serializes untrusted property values with depth, entry-count, and text-length bounds for the inspector. */
export function propertyValue(value: unknown, depth = 0): string {
  if (depth >= MAX_PROPERTY_DEPTH) return "[…]";
  if (value === null || value === undefined) return "";
  if (Array.isArray(value)) return propertyArrayValue(value, depth);
  if (typeof value === "object") return propertyObjectValue(value, depth);
  return limitPropertyText(String(value));
}

function propertyArrayValue(items: unknown[], depth: number): string {
  const values = items.slice(0, MAX_PROPERTY_ENTRIES).map((item) => propertyValue(item, depth + 1));
  return limitPropertyText(`${values.join(", ")}${truncationSuffix(items.length)}`);
}

function propertyObjectValue(value: object, depth: number): string {
  const entries = Object.entries(value)
    .slice(0, MAX_PROPERTY_ENTRIES)
    .map(([key, item]) => `${key}: ${propertyValue(item, depth + 1)}`);
  return limitPropertyText(`{${entries.join(", ")}${truncationSuffix(Object.keys(value).length)}}`);
}

function truncationSuffix(length: number): string {
  return length > MAX_PROPERTY_ENTRIES ? ", …" : "";
}

export function limitPropertyText(value: string): string {
  return value.length > MAX_PROPERTY_LENGTH ? `${value.slice(0, MAX_PROPERTY_LENGTH - 1)}…` : value;
}

/** Returns focus to the node's list entry when it is rendered, otherwise to search. */
export function returnFocus(controller: Controller, nodeId: NodeId | null = null): void {
  const entry = nodeId
    ? controller.dom.nodeList.querySelector<HTMLButtonElement>(
        `button[data-node-id="${CSS.escape(nodeId)}"]`,
      )
    : null;
  (entry ?? controller.dom.search).focus();
}
