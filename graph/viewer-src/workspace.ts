/** Synchronizes workspace panels, navigation state, and legacy tab affordances. */

import type { Controller } from "./runtime";
import type { ViewerWorkspace } from "./types";

type WorkspacePanel = [ViewerWorkspace, HTMLElement];
type WorkspaceNavigation = [ViewerWorkspace, HTMLButtonElement];

export function syncWorkspaceDom(controller: Controller, workspace: ViewerWorkspace): void {
  syncPanels(workspace, workspacePanels(controller));
  syncNavigation(workspace, workspaceNavigation(controller));
  syncExploreTabs(controller, workspace);
  controller.dom.workspaceTitle.textContent = workspaceTitle(workspace);
  controller.dom.graphContainer.dataset.workspace = workspace;
  controller.dom.pathBanner.classList.toggle(
    "visible",
    workspace === "paths" && controller.state.selection.path.active,
  );
}

function workspacePanels(controller: Controller): WorkspacePanel[] {
  return [
    ["triage", controller.dom.triageWorkspace],
    ["graph", controller.dom.graphWorkspace],
    ["paths", controller.dom.pathsWorkspace],
    ["queries", controller.dom.queriesWorkspace],
  ];
}

function workspaceNavigation(controller: Controller): WorkspaceNavigation[] {
  return [
    ["triage", controller.dom.navOverview],
    ["graph", controller.dom.navGraph],
    ["paths", controller.dom.navPaths],
    ["queries", controller.dom.navQueries],
  ];
}

function syncPanels(workspace: ViewerWorkspace, panels: WorkspacePanel[]): void {
  for (const [name, panel] of panels) panel.hidden = name !== workspace;
}

function syncNavigation(workspace: ViewerWorkspace, navigation: WorkspaceNavigation[]): void {
  for (const [name, button] of navigation) syncNavigationButton(button, name === workspace);
}

function syncNavigationButton(button: HTMLButtonElement, current: boolean): void {
  button.classList.toggle("active", current);
  button.toggleAttribute("aria-current", current);
  if (current) button.setAttribute("aria-current", "page");
}

function syncExploreTabs(controller: Controller, workspace: ViewerWorkspace): void {
  const queries = workspace === "queries";
  controller.dom.tabExplore.setAttribute("aria-selected", String(!queries));
  controller.dom.tabQueries.setAttribute("aria-selected", String(queries));
  controller.dom.explorePanel.hidden = queries;
  controller.dom.queriesPanel.hidden = !queries;
}

function workspaceTitle(workspace: ViewerWorkspace): string {
  return { triage: "Triage", graph: "Graph", paths: "Paths", queries: "Queries" }[workspace];
}
