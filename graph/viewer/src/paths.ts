/** Owns explicit source, destination, result, and reset controls for Paths. */

import { orderedNodes } from "./node-list";
import { shortestPath } from "./model";
import type { Controller } from "./runtime";

const populated = new WeakMap<Controller, Controller["state"]["graph"]>();

export function renderPathWorkspace(controller: Controller): void {
  const { pathSource, pathDestination, pathStatus } = controller.dom;
  if (populated.get(controller) !== controller.state.graph) {
    const nodes = orderedNodes(controller.state.graph);
    const fill = (select: HTMLSelectElement, placeholder: string): void => {
      select.replaceChildren(new Option(placeholder, ""));
      for (const node of nodes) select.add(new Option(node.label ?? node.id, node.id));
    };
    fill(pathSource, "Choose source");
    fill(pathDestination, "Choose destination");
    populated.set(controller, controller.state.graph);
  }
  pathSource.value = controller.state.selection.path.sourceId ?? "";
  pathDestination.value = controller.state.selection.path.targetId ?? "";
  const path = controller.state.selection.path;
  pathStatus.textContent = path.result
    ? `${Math.max(0, path.result.orderedNodeIds.length - 1)} hop modeled path retained for this session.`
    : "Choose both endpoints, then find a modeled path. Preconditions do not prove exploitation.";
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
  if (sourceId && targetId && !controller.state.selection.path.result)
    controller.dom.pathStatus.textContent =
      "No traversable modeled path was found. Choose different endpoints.";
  controller.actions.updateVisibility(controller);
}
