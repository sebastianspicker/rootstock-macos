/** Computes filter, path, and focus visibility without mutating graph state. */

import type {
  GraphEdge,
  GraphModel,
  NodeId,
  PathResult,
  ViewerNode,
  ViewerState,
  VisibilityResult,
} from "./types";

const unfilteredVisibilityByGraph = new WeakMap<GraphModel, VisibilityResult>();

export function linkKey(edge: GraphEdge): string {
  return `${edge.source}>${edge.kind}>${edge.target}`;
}

/** Gives active path and focus modes precedence over ordinary filter visibility. */
export function computeVisibility(state: ViewerState): VisibilityResult {
  const { graph, selection } = state;
  // In Graph the path is drawn over the ordinary filtered view; only Paths isolates it.
  if (state.workspace === "paths" && selection.path.active && selection.path.result)
    return pathVisibility(graph, selection.path.result);
  const visibility = baseVisibility(state);
  if (selection.path.result && !selection.focusedId)
    return withPath(graph, visibility, selection.path.result);
  return visibility;
}

function baseVisibility(state: ViewerState): VisibilityResult {
  const { graph, filters, selection } = state;
  if (selection.focusedId) return focusedVisibility(graph, selection.focusedId);
  if (filtersAreUnrestricted(filters, graph)) return unfilteredVisibility(graph);
  const nodeIds = filteredNodeIds(state);
  return { nodeIds, linkIndexes: filteredLinkIndexes(graph, filters, nodeIds) };
}

/** A retained path stays whole on the canvas even when filters hide some of its nodes. */
function withPath(graph: GraphModel, base: VisibilityResult, path: PathResult): VisibilityResult {
  const extra = pathVisibility(graph, path);
  if ([...extra.nodeIds].every((id) => base.nodeIds.has(id))) return base;
  return {
    nodeIds: new Set([...base.nodeIds, ...extra.nodeIds]),
    linkIndexes: new Set([...base.linkIndexes, ...extra.linkIndexes]),
  };
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

function hasAllKinds(
  activeKinds: ReadonlySet<string>,
  knownKinds: ReadonlyMap<string, unknown>,
): boolean {
  if (activeKinds.size !== knownKinds.size) return false;
  return [...knownKinds.keys()].every((kind) => activeKinds.has(kind));
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
  return {
    nodeIds: new Set(path.nodeIds),
    linkIndexes: new Set(
      graph.links.flatMap((edge, index) => (path.linkKeys.has(linkKey(edge)) ? [index] : [])),
    ),
  };
}

export function focusedVisibility(graph: GraphModel, focusedId: NodeId): VisibilityResult {
  const nodeIds = new Set<NodeId>([focusedId]);
  const linkIndexes = new Set<number>();
  graph.links.forEach((edge, index) => {
    if (edge.source !== focusedId && edge.target !== focusedId) return;
    nodeIds.add(edge.source);
    nodeIds.add(edge.target);
    linkIndexes.add(index);
  });
  return { nodeIds, linkIndexes };
}

export function filteredNodeIds(state: ViewerState): Set<NodeId> {
  const { graph, filters } = state;
  return new Set(
    graph.nodes.filter((node) => nodeMatchesFilters(graph, filters, node)).map((node) => node.id),
  );
}

function nodeMatchesFilters(
  graph: GraphModel,
  filters: ViewerState["filters"],
  node: ViewerNode,
): boolean {
  if (!filters.activeNodeKinds.has(node.kind)) return false;
  if (filters.searchTerm && !graph.searchTextById.get(node.id)?.includes(filters.searchTerm))
    return false;
  return !filters.vulnerabilitiesOnly || nodeIsVulnerable(node);
}

export function filteredLinkIndexes(
  graph: GraphModel,
  filters: ViewerState["filters"],
  nodeIds: Set<NodeId>,
): Set<number> {
  return nodeIds.size < graph.nodes.length / 2
    ? sparseLinkIndexes(graph, filters, nodeIds)
    : denseLinkIndexes(graph, filters, nodeIds);
}

function sparseLinkIndexes(
  graph: GraphModel,
  filters: ViewerState["filters"],
  nodeIds: Set<NodeId>,
): Set<number> {
  const linkIndexes = new Set<number>();
  for (const nodeId of nodeIds) {
    for (const candidate of graph.outgoing.get(nodeId) ?? []) {
      if (nodeIds.has(candidate.target) && edgeMatchesFilters(candidate.edge, filters))
        linkIndexes.add(candidate.linkIndex);
    }
  }
  return linkIndexes;
}

function denseLinkIndexes(
  graph: GraphModel,
  filters: ViewerState["filters"],
  nodeIds: Set<NodeId>,
): Set<number> {
  const linkIndexes = new Set<number>();
  graph.links.forEach((edge, index) => {
    if (nodeIds.has(edge.source) && nodeIds.has(edge.target) && edgeMatchesFilters(edge, filters))
      linkIndexes.add(index);
  });
  return linkIndexes;
}

function edgeMatchesFilters(edge: GraphEdge, filters: ViewerState["filters"]): boolean {
  return (
    filters.activeEdgeKinds.has(edge.kind) &&
    (!filters.attackPathsOnly || edge.properties?._traversable !== false)
  );
}

export function nodeIsVulnerable(node: ViewerNode): boolean {
  return vulnerableRisk(node) || node.properties.vulnerable === true || cveCount(node) > 0;
}

function vulnerableRisk(node: ViewerNode): boolean {
  const risk = node.properties.risk_level ?? node.properties.severity ?? "";
  return typeof risk === "string" && ["critical", "high", "medium"].includes(risk.toLowerCase());
}

function cveCount(node: ViewerNode): number {
  return Number(node.properties.cve_count ?? 0);
}
