/** Provides small DOM and display-safety primitives shared across viewer modules. */

import type {ViewerDom} from "./dom";
import type {SpatialGrid} from "./spatial";
import type {GraphPayload, NodeId, Theme, ViewerNode, ViewerState} from "./types";

export interface ViewerActions {
  applyTheme(controller: Controller, value: Theme): void;
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
  unclusteredPositions: Map<NodeId, {x: number; y: number}> | null;
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
  if (Array.isArray(value)) {
    const items = value.slice(0, MAX_PROPERTY_ENTRIES)
      .map((item) => propertyValue(item, depth + 1));
    return limitPropertyText(`${items.join(", ")}${value.length > MAX_PROPERTY_ENTRIES ? ", …" : ""}`);
  }
  if (value === null || value === undefined) return "";
  if (typeof value === "object") {
    const entries = Object.entries(value).slice(0, MAX_PROPERTY_ENTRIES)
      .map(([key, item]) => `${key}: ${propertyValue(item, depth + 1)}`);
    return limitPropertyText(`{${entries.join(", ")}${Object.keys(value).length > MAX_PROPERTY_ENTRIES ? ", …" : ""}}`);
  }
  return limitPropertyText(String(value));
}

export function limitPropertyText(value: string): string {
  return value.length > MAX_PROPERTY_LENGTH ? `${value.slice(0, MAX_PROPERTY_LENGTH - 1)}…` : value;
}
