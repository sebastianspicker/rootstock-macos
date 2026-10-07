/** Owns explicit source, destination, result, and reset controls for Paths. */

import { orderedNodes } from "./node-list";
import { displayKind, linkKey, shortestPath } from "./model";
import { element } from "./runtime";
import { riskLabel } from "./view";
import { edgeIsInferred, edgeIsTraversable } from "./canvas-edges";
import type { Controller } from "./runtime";
import type { GraphEdge, GraphModel, NodeId, PathResult, ViewerNode } from "./types";

const populated = new WeakMap<Controller, GraphModel>();
const BANNER_LABEL_LENGTH = 24;

export function renderPathWorkspace(controller: Controller): void {
  const { pathSource, pathDestination, pathStatus } = controller.dom;
  if (populated.get(controller) !== controller.state.graph) {
    fillEndpointSelect(controller.state.graph, pathSource, "Choose source");
    fillEndpointSelect(controller.state.graph, pathDestination, "Choose destination");
    populated.set(controller, controller.state.graph);
  }
  const path = controller.state.selection.path;
  pathSource.value = path.sourceId ?? "";
  pathDestination.value = path.targetId ?? "";
  pathStatus.textContent = pathStatusText(controller);
  renderPathSteps(controller);
  controller.dom.pathText.textContent = pathBannerText(controller);
}

/** Options are grouped by node kind so long snapshots stay scannable. */
function fillEndpointSelect(
  graph: GraphModel,
  select: HTMLSelectElement,
  placeholder: string,
): void {
  const groups = new Map<string, ViewerNode[]>();
  for (const node of orderedNodes(graph)) {
    const members = groups.get(node.kind) ?? [];
    members.push(node);
    groups.set(node.kind, members);
  }
  select.replaceChildren(new Option(placeholder, ""));
  for (const [kind, nodes] of [...groups.entries()].sort(([left], [right]) =>
    displayKind(left).localeCompare(displayKind(right)),
  )) {
    const group = element("optgroup", { label: displayKind(kind) });
    for (const node of nodes) group.appendChild(new Option(node.label ?? node.id, node.id));
    select.appendChild(group);
  }
}

function nodeLabel(graph: GraphModel, nodeId: NodeId | null): string {
  if (!nodeId) return "";
  const node = graph.nodeById.get(nodeId);
  return node?.label ?? nodeId;
}

function hopText(result: PathResult): string {
  const hops = Math.max(0, result.orderedNodeIds.length - 1);
  return `${hops} ${hops === 1 ? "hop" : "hops"}`;
}

function pathStatusText(controller: Controller): string {
  const { graph } = controller.state;
  const path = controller.state.selection.path;
  if (path.result) return `${hopText(path.result)} modeled path retained for this session.`;
  if (path.sourceId && path.targetId)
    return `No traversable modeled path from ${nodeLabel(graph, path.sourceId)} to ${nodeLabel(graph, path.targetId)}. Relationships are followed only in their recorded direction; try Swap endpoints to search from ${nodeLabel(graph, path.targetId)} instead.`;
  return "Choose both endpoints, then find a modeled path. Preconditions do not prove exploitation.";
}

/** Banner text for the canvas: hop count and the ordered labels, or the next step to take. */
export function pathBannerText(controller: Controller): string {
  const { graph } = controller.state;
  const path = controller.state.selection.path;
  if (path.result) {
    const labels = path.result.orderedNodeIds.map((id) => {
      const label = nodeLabel(graph, id);
      return label.length > BANNER_LABEL_LENGTH
        ? `${label.slice(0, BANNER_LABEL_LENGTH - 1)}…`
        : label;
    });
    return `${hopText(path.result)} · ${labels.join(" → ")}`;
  }
  if (path.sourceId && path.targetId)
    return "No traversable path found. Try Swap endpoints in Paths.";
  if (path.sourceId) return `Source: ${nodeLabel(graph, path.sourceId)}. Choose a destination.`;
  if (path.targetId) return `Destination: ${nodeLabel(graph, path.targetId)}. Choose a source.`;
  return "Choose explicit endpoints in Paths.";
}

/** The relationship the path search used between two consecutive nodes. */
export function pathEdge(
  graph: GraphModel,
  result: PathResult,
  from: NodeId,
  to: NodeId,
): GraphEdge | null {
  const candidates = (graph.outgoing.get(from) ?? []).filter((entry) => entry.target === to);
  const used = candidates.find((entry) => result.linkKeys.has(linkKey(entry.edge)));
  return (used ?? candidates[0])?.edge ?? null;
}

function renderPathSteps(controller: Controller): void {
  const { pathResult, pathSteps } = controller.dom;
  const result = controller.state.selection.path.result;
  pathSteps.replaceChildren();
  pathResult.hidden = !result;
  if (!result) return;
  const { graph } = controller.state;
  result.orderedNodeIds.forEach((nodeId, index) => {
    const node = graph.nodeById.get(nodeId);
    if (!node) return;
    if (index > 0) {
      const previous = result.orderedNodeIds[index - 1] ?? "";
      pathSteps.appendChild(pathEdgeStep(pathEdge(graph, result, previous, nodeId)));
    }
    pathSteps.appendChild(pathNodeStep(controller, node));
  });
}

function pathNodeStep(controller: Controller, node: ViewerNode): HTMLLIElement {
  const risk = riskLabel(node.properties.risk_level ?? node.properties.severity) || "informational";
  const inspect = element("button", {
    type: "button",
    class: "path-step-node",
    text: node.label ?? node.id,
  });
  inspect.addEventListener("click", () => controller.actions.inspectNode(controller, node.id));
  return element("li", { class: "path-step" }, [
    element("span", { class: `node-symbol node-severity-${risk}`, "aria-hidden": "true" }),
    inspect,
    element("span", { class: "path-step-kind", text: displayKind(node.kind) }),
  ]);
}

function pathEdgeStep(edge: GraphEdge | null): HTMLLIElement {
  if (!edge)
    return element("li", { class: "path-edge unknown", text: "Relationship not recorded" });
  const basis = edgeIsInferred(edge) ? "inferred" : "observed";
  const traversal = edgeIsTraversable(edge) ? "traversable" : "not traversable";
  const kind = edge.kind.replace(/^rs_/, "");
  return element(
    "li",
    { class: `path-edge ${basis}`, "aria-label": `${kind}, ${basis}, ${traversal}` },
    [
      element("code", { class: "path-edge-kind", text: kind }),
      element("span", { class: `folio-mark ${basis}`, text: basis }),
      element("span", { class: "path-edge-traversal", text: traversal }),
    ],
  );
}

export function runPath(controller: Controller): void {
  const sourceId = controller.dom.pathSource.value || null;
  const targetId = controller.dom.pathDestination.value || null;
  controller.state.selection.path = {
    active: true,
    sourceId,
    targetId,
    result: sourceId && targetId ? shortestPath(controller.state.graph, sourceId, targetId) : null,
  };
  renderPathWorkspace(controller);
  controller.actions.transitionWorkspace(controller, controller.state.workspace);
  controller.actions.updateVisibility(controller);
}

/** Paths are directed, so swapping endpoints searches the other direction. */
export function swapPathEndpoints(controller: Controller): void {
  const { pathSource, pathDestination } = controller.dom;
  const source = pathSource.value;
  pathSource.value = pathDestination.value;
  pathDestination.value = source;
  if (pathSource.value && pathDestination.value) runPath(controller);
}
