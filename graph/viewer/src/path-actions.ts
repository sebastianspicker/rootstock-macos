/** Path-mode actions: start, extend, and reset the modeled attack-path selection. */

import { shortestPath } from "./model";
import { renderPathWorkspace } from "./paths";
import { returnFocus, setPressed } from "./runtime";
import type { Controller } from "./runtime";
import type { NodeId } from "./types";
import { syncWorkspaceDom } from "./workspace";

export function resetPath(controller: Controller): void {
  const hadFocus = controller.dom.pathBanner.contains(document.activeElement);
  controller.state.selection.path = { active: false, sourceId: null, targetId: null, result: null };
  controller.dom.pathBanner.classList.remove("visible");
  setPressed(controller.dom.path, false);
  renderPathWorkspace(controller);
  if (hadFocus) returnFocus(controller);
}

export function togglePathMode(controller: Controller, sourceId: NodeId | null = null): void {
  if (controller.state.selection.path.active && sourceId === null) {
    resetPath(controller);
    controller.actions.updateVisibility(controller);
    return;
  }
  controller.state.selection.path = { active: true, sourceId, targetId: null, result: null };
  setPressed(controller.dom.path, true);
  controller.actions.transitionWorkspace(controller, "paths", true);
  renderPathWorkspace(controller);
  controller.actions.updateVisibility(controller);
}

export function startPathTo(controller: Controller, targetId: NodeId): void {
  controller.state.selection.path = { active: true, sourceId: null, targetId, result: null };
  setPressed(controller.dom.path, true);
  controller.actions.transitionWorkspace(controller, "paths", true);
  renderPathWorkspace(controller);
  controller.actions.updateVisibility(controller);
}

export function handlePathSelection(controller: Controller, nodeId: NodeId): void {
  const path = controller.state.selection.path;
  if (!path.sourceId) path.sourceId = nodeId;
  else path.targetId = nodeId;
  path.result =
    path.sourceId && path.targetId
      ? shortestPath(controller.state.graph, path.sourceId, path.targetId)
      : null;
  renderPathWorkspace(controller);
  syncWorkspaceDom(controller, controller.state.workspace);
  controller.actions.updateVisibility(controller);
  // Open the destination dossier while keeping the modeled path active.
  if (path.result && path.targetId === nodeId) controller.actions.inspectNode(controller, nodeId);
}
