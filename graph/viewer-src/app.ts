/** Coordinates viewer lifecycle, state transitions, and UI-facing graph actions. */

import {
  computeVisibility,
  createViewerState,
  deterministicClusterOffset,
  nodeRadius,
  replaceGraphModel,
  safeNodeColor,
  shortestPath,
} from "./model";
import {drawFrame, resizeCanvas, wireCanvas} from "./canvas";
import {wireControls} from "./controls";
import {collectDom} from "./dom";
import type {ViewerDom} from "./dom";
import {parseGraphPayload} from "./protocol";
import {buildFilters, renderMetadata, renderNodeList, renderRiskSummary, renderStats} from "./view";
import {readHistory, renderHistory, startLiveSession} from "./live";
import {SESSION_STORAGE_NAME} from "./storage";
import {element, setPressed} from "./runtime";
import type {Controller, ViewerActions} from "./runtime";
import {inspectNode} from "./inspector";
export {inspectNode} from "./inspector";
import {SpatialGrid} from "./spatial";
import type {
  GraphPayload,
  NodeId,
  Theme,
  ViewerNode,
  ViewerOptions,
} from "./types";

const THEME_STORAGE_NAME = "rootstock.theme";

export function nodeColor(node: ViewerNode): string { return safeNodeColor(node.properties._color); }

export function rebuildSpatial(controller: Controller): void {
  controller.spatial = new SpatialGrid(controller.state.graph.nodes, {
    isVisible: (node) => controller.state.render.visibleNodeIds.has(node.id),
    radiusFor: (node) => nodeRadius(controller.state.graph, node.id),
    positionFor: (node) => worldPosition(controller, node),
  });
}

export function updateVisibility(controller: Controller): void {
  const visibility = computeVisibility(controller.state);
  controller.state.render.visibleNodeIds = visibility.nodeIds;
  controller.state.render.visibleLinkIndexes = visibility.linkIndexes;
  renderNodeList(controller);
  renderStats(controller);
  rebuildSpatial(controller);
  markDirty(controller);
}

export function markDirty(controller: Controller): void {
  controller.state.render.dirty = true;
  if (controller.state.render.frameRequested) return;
  controller.state.render.frameRequested = true;
  requestAnimationFrame(() => drawFrame(controller, worldPosition));
}

export function worldPosition(_controller: Controller, node: ViewerNode): {x: number; y: number} {
  return {x: node.x, y: node.y};
}

export function fitViewport(controller: Controller): void {
  const nodes = controller.state.graph.nodes.filter((node) => controller.state.render.visibleNodeIds.has(node.id));
  if (nodes.length === 0) {
    controller.state.viewport.transform = {x: 0, y: 0, k: 1};
    markDirty(controller);
    return;
  }
  let minX = Number.POSITIVE_INFINITY;
  let minY = Number.POSITIVE_INFINITY;
  let maxX = Number.NEGATIVE_INFINITY;
  let maxY = Number.NEGATIVE_INFINITY;
  for (const node of nodes) {
    const position = worldPosition(controller, node);
    const radius = nodeRadius(controller.state.graph, node.id);
    const labelWidth = controller.state.selection.showLabels
      ? Math.min(240, (node.label ?? node.id).length * 7)
      : 0;
    minX = Math.min(minX, position.x - Math.max(radius, labelWidth / 2));
    minY = Math.min(minY, position.y - radius);
    maxX = Math.max(maxX, position.x + Math.max(radius, labelWidth / 2));
    maxY = Math.max(maxY, position.y + radius + (labelWidth > 0 ? 34 : 0));
  }
  const padding = 56;
  const width = Math.max(1, controller.state.viewport.width - padding * 2);
  const height = Math.max(1, controller.state.viewport.height - padding * 2);
  const k = Math.min(2, Math.max(0.08, Math.min(width / Math.max(1, maxX - minX), height / Math.max(1, maxY - minY))));
  controller.state.viewport.transform = {
    x: controller.state.viewport.width / 2 - ((minX + maxX) / 2) * k,
    y: controller.state.viewport.height / 2 - ((minY + maxY) / 2) * k,
    k,
  };
  markDirty(controller);
}

export function setClusteredLayout(controller: Controller, enabled: boolean): void {
  const {state} = controller;
  if (enabled) {
    controller.unclusteredPositions = new Map(state.graph.nodes.map((node) => [node.id, {x: node.x, y: node.y}]));
    const kinds = [...state.graph.kindMeta.keys()].sort();
    const ringRadius = Math.max(240, 150 * Math.sqrt(Math.max(1, kinds.length)));
    for (const [kindIndex, kind] of kinds.entries()) {
      const members = state.graph.nodes.filter((node) => node.kind === kind).sort((left, right) => left.id.localeCompare(right.id));
      const kindAngle = (kindIndex / Math.max(1, kinds.length)) * Math.PI * 2;
      const centerX = 1_000 + Math.cos(kindAngle) * ringRadius;
      const centerY = 1_000 + Math.sin(kindAngle) * ringRadius;
      for (const [index, node] of members.entries()) {
        const angle = (index / Math.max(1, members.length)) * Math.PI * 2;
        const localRadius = 42 + Math.min(120, Math.sqrt(members.length) * 15);
        node.x = centerX + Math.cos(angle) * localRadius + deterministicClusterOffset(node.id) * 0.25;
        node.y = centerY + Math.sin(angle) * localRadius + deterministicClusterOffset(`${node.id}:y`) * 0.25;
      }
    }
  } else if (controller.unclusteredPositions) {
    for (const node of state.graph.nodes) {
      const position = controller.unclusteredPositions.get(node.id);
      if (position) Object.assign(node, position);
    }
    controller.unclusteredPositions = null;
  }
  state.selection.clustered = enabled;
  rebuildSpatial(controller);
  fitViewport(controller);
}


export function closeInspector(controller: Controller): void {
  controller.state.selection.selectedId = null;
  controller.state.selection.pinnedId = null;
  controller.dom.inspector.classList.remove("open");
  controller.dom.inspectorBody.textContent = "";
  controller.dom.detailEmpty.hidden = controller.dom.resultsPanel.classList.contains("open");
  renderNodeList(controller);
  markDirty(controller);
}

export function closeResults(controller: Controller): void {
  controller.dom.resultsPanel.classList.remove("open");
  controller.dom.resultsBody.textContent = "";
  controller.dom.resultsMeta.textContent = "";
  controller.dom.detailEmpty.hidden = controller.dom.inspector.classList.contains("open");
}

export function viewerNode(controller: Controller, nodeId: NodeId): ViewerNode | null {
  return controller.state.graph.nodeById.get(nodeId) ?? null;
}

export function enterFocusMode(controller: Controller, nodeId: NodeId): void {
  const node = viewerNode(controller, nodeId);
  if (!node) return;
  controller.state.selection.focusedId = nodeId;
  controller.dom.focusText.textContent = `Focused on ${node.label ?? node.id} and one-hop neighbors`;
  controller.dom.focusBanner.classList.add("visible");
  updateVisibility(controller);
}

export function exitFocusMode(controller: Controller): void {
  controller.state.selection.focusedId = null;
  controller.dom.focusBanner.classList.remove("visible");
  updateVisibility(controller);
}

export function resetPath(controller: Controller): void {
  controller.state.selection.path = {active: false, sourceId: null, targetId: null, result: null};
  controller.dom.pathBanner.classList.remove("visible");
  controller.dom.pathText.textContent = "Choose a source node from the graph or node list.";
  setPressed(controller.dom.path, false);
  controller.dom.navPaths.classList.remove("active");
  controller.dom.navPaths.removeAttribute("aria-current");
  if (!controller.dom.queriesPanel.hidden) return;
  controller.dom.navGraph.classList.add("active");
  controller.dom.navGraph.setAttribute("aria-current", "page");
}

export function togglePathMode(controller: Controller, sourceId: NodeId | null = null): void {
  if (controller.state.selection.path.active && sourceId === null) {
    resetPath(controller);
    updateVisibility(controller);
    return;
  }
  controller.state.selection.path = {active: true, sourceId, targetId: null, result: null};
  controller.dom.pathBanner.classList.add("visible");
  controller.dom.pathText.textContent = sourceId
    ? "Choose a destination node."
    : "Choose a source node from the graph or node list.";
  setPressed(controller.dom.path, true);
  controller.dom.navGraph.classList.remove("active");
  controller.dom.navGraph.removeAttribute("aria-current");
  controller.dom.navPaths.classList.add("active");
  controller.dom.navPaths.setAttribute("aria-current", "page");
  updateVisibility(controller);
}

export function startPathTo(controller: Controller, targetId: NodeId): void {
  controller.state.selection.path = {active: true, sourceId: null, targetId, result: null};
  controller.dom.pathBanner.classList.add("visible");
  controller.dom.pathText.textContent = "Choose a source node.";
  setPressed(controller.dom.path, true);
  updateVisibility(controller);
}

export function handlePathSelection(controller: Controller, nodeId: NodeId): void {
  const path = controller.state.selection.path;
  if (!path.sourceId) {
    path.sourceId = nodeId;
    if (path.targetId) {
      path.result = shortestPath(controller.state.graph, nodeId, path.targetId);
      controller.dom.pathText.textContent = path.result
        ? `${Math.max(0, path.result.orderedNodeIds.length - 1)} hop(s)`
        : "No traversable path found. Choose another source or cancel.";
      updateVisibility(controller);
      return;
    }
    const node = controller.state.graph.nodeById.get(nodeId);
    controller.dom.pathText.textContent = `Source: ${node?.label ?? nodeId}. Choose a destination node.`;
    return;
  }
  path.targetId = nodeId;
  path.result = shortestPath(controller.state.graph, path.sourceId, nodeId);
  if (!path.result) {
    controller.dom.pathText.textContent = "No traversable path found. Choose another destination or cancel.";
    return;
  }
  const hops = Math.max(0, path.result.orderedNodeIds.length - 1);
  controller.dom.pathText.textContent = `${hops} ${hops === 1 ? "hop" : "hops"}`;
  updateVisibility(controller);
  // Open the destination dossier while keeping the modeled path active.
  inspectNode(controller, nodeId);
}

export function centerOnNode(controller: Controller, node: ViewerNode): void {
  const position = worldPosition(controller, node);
  const k = 1.5;
  controller.state.viewport.transform = {
    x: controller.state.viewport.width / 2 - position.x * k,
    y: controller.state.viewport.height / 2 - position.y * k,
    k,
  };
  markDirty(controller);
}

export function hideContextMenu(controller: Controller): void {
  controller.dom.contextMenu.replaceChildren();
  controller.dom.contextMenu.style.display = "none";
}

export function showContextMenu(controller: Controller, event: MouseEvent, node: ViewerNode): void {
  event.preventDefault();
  const {contextMenu, graphContainer} = controller.dom;
  contextMenu.replaceChildren();
  const action = (label: string, handler: () => void): HTMLButtonElement => {
    const button = element("button", {class: "ctx-item", type: "button", text: label});
    button.addEventListener("click", () => {
      hideContextMenu(controller);
      handler();
    });
    return button;
  };
  contextMenu.append(
    action("Find paths from this node", () => togglePathMode(controller, node.id)),
    action("Find paths to this node", () => startPathTo(controller, node.id)),
    action("Show neighbors only", () => enterFocusMode(controller, node.id)),
    action("Center on this node", () => centerOnNode(controller, node)),
  );
  for (const tier of [0, 1, 2]) {
    contextMenu.append(action(`Set local tier ${tier}`, () => {
      node.properties.tier = tier;
      inspectNode(controller, node.id);
    }));
  }
  contextMenu.append(action("Clear local tier", () => {
    delete node.properties.tier;
    inspectNode(controller, node.id);
  }));
  const rect = graphContainer.getBoundingClientRect();
  contextMenu.style.left = `${event.clientX - rect.left}px`;
  contextMenu.style.top = `${event.clientY - rect.top}px`;
  contextMenu.style.display = "block";
}

export function selectNode(controller: Controller, nodeId: NodeId): void {
  if (controller.state.selection.path.active) {
    handlePathSelection(controller, nodeId);
    return;
  }
  inspectNode(controller, nodeId);
}

export function resetInteractionUi(controller: Controller): void {
  controller.dom.focusBanner.classList.remove("visible");
  controller.dom.pathBanner.classList.remove("visible");
  controller.dom.inspector.classList.remove("open");
  controller.dom.resultsPanel.classList.remove("open");
  controller.dom.detailEmpty.hidden = false;
  setPressed(controller.dom.path, false);
  setPressed(controller.dom.cluster, false);
  setPressed(controller.dom.vulnerable, false);
  setPressed(controller.dom.attack, false);
  controller.dom.search.value = "";
}

/** Replaces every graph-derived UI state so a refresh cannot retain stale selections or filters. */
export function replaceGraph(controller: Controller, payload: GraphPayload): void {
  replaceGraphModel(controller.state, payload);
  controller.unclusteredPositions = null;
  resetInteractionUi(controller);
  renderMetadata(controller);
  renderRiskSummary(controller);
  buildFilters(controller);
  updateVisibility(controller);
  fitViewport(controller);
}

export function applyTheme(controller: Controller, value: Theme): void {
  if (value === "system") {
    document.documentElement.removeAttribute("data-theme");
    document.body.removeAttribute("data-theme");
  } else {
    document.documentElement.setAttribute("data-theme", value);
    document.body.setAttribute("data-theme", value);
  }
  localStorage.setItem(THEME_STORAGE_NAME, value);
  markDirty(controller);
}

export function selectTab(controller: Controller, tab: "explore" | "queries"): void {
  const explore = tab === "explore";
  controller.dom.tabExplore.setAttribute("aria-selected", String(explore));
  controller.dom.tabQueries.setAttribute("aria-selected", String(!explore));
  controller.dom.explorePanel.hidden = !explore;
  controller.dom.queriesPanel.hidden = explore;
  controller.dom.navOverview.classList.remove("active");
  controller.dom.navPaths.classList.toggle("active", explore && controller.state.selection.path.active);
  controller.dom.navGraph.classList.toggle("active", explore && !controller.state.selection.path.active);
  controller.dom.navQueries.classList.toggle("active", !explore);
  controller.dom.navPaths.toggleAttribute("aria-current", explore && controller.state.selection.path.active);
  controller.dom.navGraph.toggleAttribute("aria-current", explore && !controller.state.selection.path.active);
  controller.dom.navQueries.toggleAttribute("aria-current", !explore);
}

export function setLiveStatus(controller: Controller, message: string, state = ""): void {
  controller.dom.liveStatus.textContent = message;
  controller.dom.liveStatus.className = `live-status${state ? ` ${state}` : ""}`;
}

export function showConnectionGate(controller: Controller, message = ""): void {
  controller.dom.connectionGate.hidden = false;
  controller.dom.connectionError.textContent = message;
  controller.dom.connectionError.hidden = message.length === 0;
  controller.dom.connectionStatus.textContent = message ? "Connection required" : "Not connected";
  controller.dom.connectionStatus.className = `status-chip${message ? " error" : ""}`;
}

export function hideConnectionGate(controller: Controller): void {
  controller.dom.connectionGate.hidden = true;
  controller.dom.connectionStatus.textContent = "Live · connected";
  controller.dom.connectionStatus.className = "status-chip connected";
}

export function resetViewport(controller: Controller): void {
  fitViewport(controller);
}

export function zoomViewport(controller: Controller, factor: number): void {
  const transform = controller.state.viewport.transform;
  const nextK = Math.max(0.08, Math.min(4, transform.k * factor));
  const centerX = controller.state.viewport.width / 2;
  const centerY = controller.state.viewport.height / 2;
  const worldX = (centerX - transform.x) / transform.k;
  const worldY = (centerY - transform.y) / transform.k;
  transform.k = nextK;
  transform.x = centerX - worldX * nextK;
  transform.y = centerY - worldY * nextK;
  markDirty(controller);
}

export function exportPng(controller: Controller): void {
  const link = document.createElement("a");
  link.download = "rootstock-graph.png";
  link.href = controller.dom.canvas.toDataURL("image/png");
  link.click();
}

export function configureMode(controller: Controller): void {
  if (!controller.state.live.enabled) {
    controller.dom.connectionStatus.textContent = "Local session · offline";
    controller.dom.connectionGate.hidden = true;
    return;
  }
  controller.dom.liveActions.classList.add("live");
  controller.dom.customQuerySection.hidden = false;
  if (sessionStorage.getItem(SESSION_STORAGE_NAME)) startLiveSession(controller);
  else showConnectionGate(controller);
}

export function viewerActions(): ViewerActions {
  return {
    applyTheme, closeInspector, closeResults, enterFocusMode, exitFocusMode, exportPng,
    hideConnectionGate, hideContextMenu, inspectNode, markDirty, replaceGraph,
    resetPath, resetViewport, selectNode, selectTab, setClusteredLayout,
    setLiveStatus, showConnectionGate, togglePathMode, updateVisibility, zoomViewport,
  };
}

function controllerForPayload(payload: ReturnType<typeof parseGraphPayload>, options: ViewerOptions, dom: ViewerDom): Controller {
  const state = createViewerState(payload, options.mode === "live", options.apiBaseUrl ?? "");
  return {
    state,
    dom,
    spatial: new SpatialGrid(state.graph.nodes),
    unclusteredPositions: null,
    actions: viewerActions(),
  };
}

export function createController(input: unknown, options: ViewerOptions): Controller {
  return controllerForPayload(parseGraphPayload(input), options, collectDom());
}

export function initializeController(controller: Controller): void {
  renderMetadata(controller);
  renderRiskSummary(controller);
  buildFilters(controller);
  renderHistory(controller, readHistory());
  wireControls(controller);
  wireCanvas(controller, {closeInspector, hideContextMenu, markDirty, rebuildSpatial, selectNode, showContextMenu, worldPosition});
  const savedTheme = localStorage.getItem(THEME_STORAGE_NAME);
  const theme: Theme = savedTheme === "light" || savedTheme === "system" ? savedTheme : "dark";
  controller.dom.themeSelect.value = theme;
  applyTheme(controller, theme);
  updateVisibility(controller);
  configureMode(controller);
}

export function observeViewport(controller: Controller): void {
  const resize = (): void => resizeCanvas(controller, () => fitViewport(controller));
  const resizeObserver = new ResizeObserver(resize);
  resizeObserver.observe(controller.dom.graphContainer);
  resize();
}

/** Mounts one viewer instance after validating its payload and wiring its DOM lifecycle. */
export function mount(input: unknown, options: ViewerOptions = {}): void {
  const payload = parseGraphPayload(input);
  const dom = collectDom();
  const controller = controllerForPayload(payload, options, dom);
  initializeController(controller);
  observeViewport(controller);
}
