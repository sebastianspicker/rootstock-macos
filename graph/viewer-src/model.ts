/** Builds deterministic graph indexes and computes filtering, focus, and directed attack-path state. */

import type {
  GraphEdge,
  GraphModel,
  IncomingEdge,
  EdgeMeta,
  KindMeta,
  GraphPayload,
  NodeId,
  OutgoingEdge,
  PathResult,
  ViewerNode,
  ViewerState,
  VisibilityResult,
} from "./types";

const unfilteredVisibilityByGraph = new WeakMap<GraphModel, VisibilityResult>();

const DEFAULT_COLOR = "#8c99a8";
const HEX_COLOR = /^#(?:[\da-f]{3,4}|[\da-f]{6}|[\da-f]{8})$/i;

export function digits(value: string): boolean {
  return value.length > 0 && [...value].every((character) => character >= "0" && character <= "9");
}

export function decimal(value: string): boolean {
  const parts = value.split(".");
  return parts.length <= 2 && parts.every(digits);
}

export function percentage(value: string): boolean {
  return value.endsWith("%") && decimal(value.slice(0, -1)) && Number(value.slice(0, -1)) <= 100;
}

function rgbChannel(value: string): boolean {
  return percentage(value) || (digits(value) && Number(value) <= 255);
}

export function alphaChannel(value: string): boolean {
  if (percentage(value)) return true;
  const normalized = value.startsWith(".") ? `0${value}` : value;
  return decimal(normalized) && Number(normalized) >= 0 && Number(normalized) <= 1;
}

export function functionalColor(value: string): boolean {
  const parsed = colorComponents(value);
  if (!parsed) return false;
  return parsed.name.startsWith("rgb")
    ? rgbComponents(parsed.parts)
    : hslComponents(parsed.parts);
}

type FunctionalColor = {name: "rgb" | "rgba" | "hsl" | "hsla"; parts: string[]};

export function colorComponents(value: string): FunctionalColor | null {
  const parsed = parenthesizedValue(value);
  if (!parsed) return null;
  const name = parsed.name.toLowerCase();
  if (!functionalName(name)) return null;
  const parts = parsed.body.split(",").map((part) => part.trim());
  return expectedComponentCount(name, parts.length) ? {name, parts} : null;
}

export function parenthesizedValue(value: string): {name: string; body: string} | null {
  const open = value.indexOf("(");
  if (open < 1) return null;
  if (!value.endsWith(")")) return null;
  return {name: value.slice(0, open), body: value.slice(open + 1, -1)};
}

export function functionalName(value: string): value is FunctionalColor["name"] {
  return ["rgb", "rgba", "hsl", "hsla"].includes(value);
}

export function expectedComponentCount(name: FunctionalColor["name"], count: number): boolean {
  return count === (name.endsWith("a") ? 4 : 3);
}

export function rgbComponents(parts: string[]): boolean {
  return parts.slice(0, 3).every(rgbChannel) && optionalAlpha(parts);
}

export function hslComponents(parts: string[]): boolean {
  return hslTriplet(parts) && optionalAlpha(parts);
}

export function hslTriplet(parts: string[]): boolean {
  return [
    hueChannel(parts[0] ?? ""),
    percentage(parts[1] ?? ""),
    percentage(parts[2] ?? ""),
  ].every(Boolean);
}

export function optionalAlpha(parts: string[]): boolean {
  return parts.length < 4 || alphaChannel(parts[3] ?? "");
}

export function hueChannel(value: string): boolean {
  const unsigned = value.startsWith("-") ? value.slice(1) : value;
  const unit = ["grad", "turn", "deg", "rad"].find((candidate) => unsigned.endsWith(candidate));
  const magnitude = unit ? unsigned.slice(0, -unit.length) : unsigned;
  return decimal(magnitude);
}

export function safeNodeColor(value: unknown): string {
  if (typeof value !== "string") return DEFAULT_COLOR;
  const color = value.trim();
  return HEX_COLOR.test(color) || functionalColor(color)
    ? color
    : DEFAULT_COLOR;
}

export function displayKind(kind: string): string {
  return kind.replace(/^rs_/, "").replace(/([A-Z])/g, " $1").trim();
}

export function numericProperty(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

export function searchableNodeText(node: ViewerNode): string {
  const values = [
    node.id,
    node.kind,
    node.label,
    node.properties.bundle_id,
    node.properties.name,
    node.properties.service,
    node.properties.path,
    node.properties.source,
    node.properties.finding_id,
    node.properties.severity,
    node.properties.category,
  ];
  return values.filter((value): value is string => typeof value === "string")
    .join("\n")
    .toLowerCase();
}

export function linkKey(edge: GraphEdge): string {
  return `${edge.source}>${edge.kind}>${edge.target}`;
}

export function deterministicClusterOffset(id: NodeId): number {
  let hash = 2166136261;
  for (const character of id) {
    hash ^= character.charCodeAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return ((hash >>> 0) % 101) - 50;
}

function normalizeNode(node: GraphPayload["graph"]["nodes"][number], index: number): ViewerNode {
  const columns = Math.max(1, Math.ceil(Math.sqrt(1 + index)));
  return {
    ...node,
    x: numericProperty(node.x) ?? 120 + (index % columns) * 90,
    y: numericProperty(node.y) ?? 120 + Math.floor(index / columns) * 90,
    properties: {...(node.properties ?? {})},
  };
}

function normalizeEdges(payload: GraphPayload): GraphEdge[] {
  return payload.graph.edges.map((edge) => ({
    ...edge,
    properties: {...(edge.properties ?? {})},
  }));
}

function buildNodeIndexes(nodes: ViewerNode[]): Pick<GraphModel, "nodeById" | "searchTextById" | "kindMeta"> {
  const nodeById = new Map<NodeId, ViewerNode>(nodes.map((node) => [node.id, node]));
  const searchTextById = new Map<NodeId, string>();
  const kindMeta = new Map<string, KindMeta>();
  for (const node of nodes) {
    searchTextById.set(node.id, searchableNodeText(node));
    updateKindMeta(kindMeta, node);
  }
  return {nodeById, searchTextById, kindMeta};
}

function updateKindMeta(kindMeta: Map<string, KindMeta>, node: ViewerNode): void {
  const existing = kindMeta.get(node.kind);
  if (existing) {
    existing.count += 1;
  } else {
    kindMeta.set(node.kind, {
      color: safeNodeColor(node.properties._color),
      count: 1,
      label: displayKind(node.kind),
    });
  }
}

function buildEdgeIndexes(links: GraphEdge[]): Pick<GraphModel, "degreeById" | "edgeMeta" | "outgoing" | "incoming"> {
  const degreeById = new Map<NodeId, number>();
  const edgeMeta = new Map<string, EdgeMeta>();
  const outgoing = new Map<NodeId, OutgoingEdge[]>();
  const incoming = new Map<NodeId, IncomingEdge[]>();
  links.forEach((edge, linkIndex) => {
    updateDegree(degreeById, edge);
    updateEdgeMeta(edgeMeta, edge);
    appendDirectedEdge(outgoing, edge.source, {target: edge.target, edge, linkIndex});
    appendDirectedEdge(incoming, edge.target, {source: edge.source, edge, linkIndex});
  });
  return {degreeById, edgeMeta, outgoing, incoming};
}

function updateDegree(degreeById: Map<NodeId, number>, edge: GraphEdge): void {
  degreeById.set(edge.source, (degreeById.get(edge.source) ?? 0) + 1);
  degreeById.set(edge.target, (degreeById.get(edge.target) ?? 0) + 1);
}

function updateEdgeMeta(edgeMeta: Map<string, EdgeMeta>, edge: GraphEdge): void {
  const traversable = edge.properties?._traversable === true;
  const existing = edgeMeta.get(edge.kind);
  if (existing) {
    existing.count += 1;
    existing.traversable ||= traversable;
    return;
  }
  edgeMeta.set(edge.kind, {count: 1, label: displayKind(edge.kind), traversable});
}

function appendDirectedEdge<T>(index: Map<NodeId, T[]>, nodeId: NodeId, entry: T): void {
  const edges = index.get(nodeId) ?? [];
  edges.push(entry);
  index.set(nodeId, edges);
}

/** Normalizes payload data and builds the indexes shared by rendering, filters, and traversal. */
export function buildGraphModel(payload: GraphPayload): GraphModel {
  const nodes = payload.graph.nodes.map(normalizeNode);
  const edges = normalizeEdges(payload);
  const nodeIndexes = buildNodeIndexes(nodes);
  const links = edges.filter((edge) => nodeIndexes.nodeById.has(edge.source) && nodeIndexes.nodeById.has(edge.target));
  const edgeIndexes = buildEdgeIndexes(links);

  return {
    payload: {
      metadata: {...(payload.metadata ?? {})},
      graph: {nodes, edges},
    },
    nodes,
    edges,
    links,
    ...nodeIndexes,
    ...edgeIndexes,
  };
}

export function createViewerState(payload: GraphPayload, live: boolean, apiBaseUrl: string): ViewerState {
  const graph = buildGraphModel(payload);
  return {
    graph,
    filters: {
      activeNodeKinds: new Set(graph.kindMeta.keys()),
      activeEdgeKinds: new Set(graph.edgeMeta.keys()),
      searchTerm: "",
      attackPathsOnly: false,
      vulnerabilitiesOnly: false,
    },
    selection: {
      selectedId: null,
      hoveredId: null,
      pinnedId: null,
      focusedId: null,
      path: {active: false, sourceId: null, targetId: null, result: null},
      clustered: false,
      showLabels: true,
    },
    viewport: {
      transform: {x: 0, y: 0, k: 1},
      width: 1,
      height: 1,
      devicePixelRatio: 1,
    },
    pointer: {
      draggedId: null,
      dragOffset: {x: 0, y: 0},
      panning: false,
      panStart: {x: 0, y: 0},
      mouseDown: {x: 0, y: 0},
      didDrag: false,
      suppressClick: false,
    },
    render: {
      dirty: true,
      frameRequested: false,
      visibleNodeIds: new Set(),
      visibleLinkIndexes: new Set(),
    },
    live: {enabled: live, apiBaseUrl, refreshGeneration: 0},
  };
}

export function replaceGraphModel(state: ViewerState, payload: GraphPayload): void {
  state.graph = buildGraphModel(payload);
  resetFilters(state);
  resetSelection(state);
  state.pointer.draggedId = null;
  state.pointer.panning = false;
  state.pointer.didDrag = false;
}

export function resetFilters(state: ViewerState): void {
  state.filters.activeNodeKinds = new Set(state.graph.kindMeta.keys());
  state.filters.activeEdgeKinds = new Set(state.graph.edgeMeta.keys());
  state.filters.searchTerm = "";
  state.filters.attackPathsOnly = false;
  state.filters.vulnerabilitiesOnly = false;
}

export function resetSelection(state: ViewerState): void {
  state.selection.selectedId = null;
  state.selection.hoveredId = null;
  state.selection.pinnedId = null;
  state.selection.focusedId = null;
  state.selection.path = {active: false, sourceId: null, targetId: null, result: null};
  state.selection.clustered = false;
}

export function nodeIsVulnerable(node: ViewerNode): boolean {
  return vulnerableRisk(node) || node.properties.vulnerable === true || cveCount(node) > 0;
}

export function vulnerableRisk(node: ViewerNode): boolean {
  const risk = node.properties.risk_level ?? node.properties.severity ?? "";
  return typeof risk === "string" && ["critical", "high", "medium"].includes(risk.toLowerCase());
}

export function cveCount(node: ViewerNode): number {
  return Number(node.properties.cve_count ?? 0);
}

/** Gives active path and focus modes precedence over ordinary filter visibility. */
export function computeVisibility(state: ViewerState): VisibilityResult {
  const {graph, filters, selection} = state;
  if (selection.path.active && selection.path.result) {
    return pathVisibility(graph, selection.path.result);
  }
  if (selection.focusedId) {
    return focusedVisibility(graph, selection.focusedId);
  }
  if (filtersAreUnrestricted(filters, graph)) {
    return unfilteredVisibility(graph);
  }
  const nodeIds = filteredNodeIds(state);
  return {nodeIds, linkIndexes: filteredLinkIndexes(graph, filters, nodeIds)};
}

function filtersAreUnrestricted(filters: ViewerState["filters"], graph: GraphModel): boolean {
  return [
    hasAllKinds(filters.activeNodeKinds, graph.kindMeta),
    hasAllKinds(filters.activeEdgeKinds, graph.edgeMeta),
    !filters.searchTerm,
    !filters.attackPathsOnly,
    !filters.vulnerabilitiesOnly,
  ].every(Boolean);
}

function hasAllKinds(activeKinds: ReadonlySet<string>, knownKinds: ReadonlyMap<string, unknown>): boolean {
  if (activeKinds.size !== knownKinds.size) return false;
  for (const kind of knownKinds.keys()) {
    if (!activeKinds.has(kind)) return false;
  }
  return true;
}

function unfilteredVisibility(graph: GraphModel): VisibilityResult {
  const cached = unfilteredVisibilityByGraph.get(graph);
  if (cached) return cached;
  const visibility = {
    nodeIds: new Set(graph.nodes.map((node) => node.id)),
    linkIndexes: new Set(graph.links.keys()),
  };
  unfilteredVisibilityByGraph.set(graph, visibility);
  return visibility;
}

export function pathVisibility(graph: GraphModel, path: PathResult): VisibilityResult {
  const nodeIds = new Set(path.nodeIds);
  const linkIndexes = new Set<number>();
  graph.links.forEach((edge, index) => {
    if (path.linkKeys.has(linkKey(edge))) linkIndexes.add(index);
  });
  return {nodeIds, linkIndexes};
}

export function focusedVisibility(graph: GraphModel, focusedId: NodeId): VisibilityResult {
  const nodeIds = new Set<NodeId>([focusedId]);
  const linkIndexes = new Set<number>();
  graph.links.forEach((edge, index) => {
    if (edge.source === focusedId || edge.target === focusedId) {
      nodeIds.add(edge.source);
      nodeIds.add(edge.target);
      linkIndexes.add(index);
    }
  });
  return {nodeIds, linkIndexes};
}

export function filteredNodeIds(state: ViewerState): Set<NodeId> {
  const {graph, filters} = state;
  const nodeIds = new Set<NodeId>();
  for (const node of graph.nodes) {
    if (!filters.activeNodeKinds.has(node.kind)) continue;
    if (filters.searchTerm && !graph.searchTextById.get(node.id)?.includes(filters.searchTerm)) continue;
    if (filters.vulnerabilitiesOnly && !nodeIsVulnerable(node)) continue;
    nodeIds.add(node.id);
  }
  return nodeIds;
}

export function filteredLinkIndexes(
  graph: GraphModel,
  filters: ViewerState["filters"],
  nodeIds: Set<NodeId>,
): Set<number> {
  const linkIndexes = new Set<number>();
  if (nodeIds.size < graph.nodes.length / 2) {
    for (const nodeId of nodeIds) {
      for (const candidate of graph.outgoing.get(nodeId) ?? []) {
        if (!nodeIds.has(candidate.target)) continue;
        if (!edgeMatchesFilters(candidate.edge, filters)) continue;
        linkIndexes.add(candidate.linkIndex);
      }
    }
    return linkIndexes;
  }
  graph.links.forEach((edge, index) => {
    if (!nodeIds.has(edge.source) || !nodeIds.has(edge.target)) return;
    if (!edgeMatchesFilters(edge, filters)) return;
    linkIndexes.add(index);
  });
  return linkIndexes;
}

function edgeMatchesFilters(edge: GraphEdge, filters: ViewerState["filters"]): boolean {
  if (!filters.activeEdgeKinds.has(edge.kind)) return false;
  return !filters.attackPathsOnly || edge.properties?._traversable === true;
}

export function nodeRadius(model: GraphModel, nodeId: NodeId): number {
  return Math.min(22 + Math.sqrt(model.degreeById.get(nodeId) ?? 0) * 4, 34);
}

/** Finds the shortest directed path using edges unless they explicitly opt out of traversal. */
export function shortestPath(model: GraphModel, sourceId: NodeId, targetId: NodeId): PathResult | null {
  if (!model.nodeById.has(sourceId) || !model.nodeById.has(targetId)) return null;
  if (sourceId === targetId) {
    return {nodeIds: new Set([sourceId]), linkKeys: new Set(), orderedNodeIds: [sourceId]};
  }
  const previous = breadthFirstPrevious(model, sourceId, targetId);
  return previous ? reconstructPath(previous, sourceId, targetId) : null;
}

type PreviousStep = {nodeId: NodeId; edge: GraphEdge};

/** Performs FIFO directed traversal and records the first predecessor for deterministic path reconstruction. */
export function breadthFirstPrevious(model: GraphModel, sourceId: NodeId, targetId: NodeId): Map<NodeId, PreviousStep> | null {
  const queue: NodeId[] = [sourceId];
  const previous = new Map<NodeId, PreviousStep>();
  const visited = new Set<NodeId>([sourceId]);
  for (let index = 0; index < queue.length; index += 1) {
    const current = queue[index];
    if (!current) continue;
    if (visitCandidates(model, current, targetId, visited, previous, queue)) return previous;
  }
  return null;
}

export function visitCandidates(
  model: GraphModel,
  current: NodeId,
  targetId: NodeId,
  visited: Set<NodeId>,
  previous: Map<NodeId, PreviousStep>,
  queue: NodeId[],
): boolean {
  for (const candidate of model.outgoing.get(current) ?? []) {
    if (!canVisit(candidate.target, candidate.edge, visited)) continue;
    visited.add(candidate.target);
    previous.set(candidate.target, {nodeId: current, edge: candidate.edge});
    if (candidate.target === targetId) return true;
    queue.push(candidate.target);
  }
  return false;
}

export function canVisit(targetId: NodeId, edge: GraphEdge, visited: Set<NodeId>): boolean {
  return edge.properties?._traversable !== false && !visited.has(targetId);
}

export function reconstructPath(previous: Map<NodeId, PreviousStep>, sourceId: NodeId, targetId: NodeId): PathResult | null {
  const orderedNodeIds: NodeId[] = [targetId];
  const linkKeys = new Set<string>();
  for (let cursor = targetId; cursor !== sourceId;) {
    const step = previous.get(cursor);
    if (!step) return null;
    linkKeys.add(linkKey(step.edge));
    cursor = step.nodeId;
    orderedNodeIds.push(cursor);
  }
  orderedNodeIds.reverse();
  return {nodeIds: new Set(orderedNodeIds), linkKeys, orderedNodeIds};
}
