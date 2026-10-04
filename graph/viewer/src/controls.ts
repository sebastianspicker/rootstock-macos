/** Connects the viewer's controls and keyboard shortcuts to controller actions. */

import { setPressed } from "./runtime";
import {
  liveRefresh,
  liveShowOwned,
  liveTierClassify,
  renderHistory,
  runCustomCypher,
  startLiveSession,
} from "./live";
import { HISTORY_STORAGE_NAME, setApiToken } from "./storage";
import { buildFilters } from "./view";
import { resetFilters } from "./model";
import { runPath } from "./paths";
import type { Controller } from "./runtime";
import type { ViewerDom } from "./dom";
import type { Theme } from "./types";

export function wireControls(controller: Controller): void {
  wireFilterControls(controller);
  wireWorkspaceControls(controller);
  wireGraphControls(controller);
  wirePathControls(controller);
  wireInspectorControls(controller);
  wireQueryControls(controller);
  wireLiveControls(controller);
  document.addEventListener("click", () => controller.actions.hideContextMenu(controller));
  wireKeyboardShortcuts(controller, controller.dom);
}

function wireFilterControls(controller: Controller): void {
  const { state, dom } = controller;
  dom.search.addEventListener("input", () => {
    state.filters.searchTerm = dom.search.value.trim().toLowerCase();
    controller.actions.updateVisibility(controller);
    dom.searchStatus.textContent = `${state.render.visibleNodeIds.size} matching node(s)`;
  });
  dom.clearSearch.addEventListener("click", () => {
    dom.search.value = "";
    state.filters.searchTerm = "";
    dom.searchStatus.textContent = "";
    controller.actions.updateVisibility(controller);
    dom.search.focus();
  });
  dom.clearFilters.addEventListener("click", () => {
    resetFilters(state);
    dom.search.value = "";
    buildFilters(controller);
    controller.actions.updateVisibility(controller);
  });
}

function wireWorkspaceControls(controller: Controller): void {
  const { dom } = controller;
  dom.tabExplore.addEventListener("click", () =>
    controller.actions.selectTab(controller, "explore"),
  );
  dom.tabQueries.addEventListener("click", () =>
    controller.actions.selectTab(controller, "queries"),
  );
  dom.navOverview.addEventListener("click", () => {
    controller.actions.transitionWorkspace(controller, "triage", true);
  });
  dom.navPaths.addEventListener("click", () => {
    controller.actions.transitionWorkspace(controller, "paths", true);
  });
  dom.navGraph.addEventListener("click", () => {
    controller.actions.transitionWorkspace(controller, "graph", true);
    controller.actions.resetViewport(controller);
  });
  dom.navQueries.addEventListener("click", () =>
    controller.actions.transitionWorkspace(controller, "queries", true),
  );
  dom.navExports.addEventListener("click", () => controller.actions.exportPng(controller));
  dom.navSettings.addEventListener("click", () => dom.themeSelect.focus());
}

function wireGraphControls(controller: Controller): void {
  const { state, dom } = controller;
  dom.reset.addEventListener("click", () => controller.actions.resetViewport(controller));
  dom.labels.addEventListener("click", () => {
    state.selection.showLabels = !state.selection.showLabels;
    setPressed(dom.labels, state.selection.showLabels);
    controller.actions.markDirty(controller);
  });
  dom.cluster.addEventListener("click", () => {
    controller.actions.setClusteredLayout(controller, !state.selection.clustered);
    setPressed(dom.cluster, state.selection.clustered);
  });
  dom.attack.addEventListener("click", () => {
    state.filters.attackPathsOnly = !state.filters.attackPathsOnly;
    setPressed(dom.attack, state.filters.attackPathsOnly);
    controller.actions.updateVisibility(controller);
  });
  dom.path.addEventListener("click", () =>
    controller.actions.transitionWorkspace(controller, "paths", true),
  );
  dom.vulnerable.addEventListener("click", () => {
    state.filters.vulnerabilitiesOnly = !state.filters.vulnerabilitiesOnly;
    setPressed(dom.vulnerable, state.filters.vulnerabilitiesOnly);
    controller.actions.updateVisibility(controller);
  });
  dom.exportPng.addEventListener("click", () => controller.actions.exportPng(controller));
  dom.zoomIn.addEventListener("click", () => controller.actions.zoomViewport(controller, 1.25));
  dom.zoomOut.addEventListener("click", () => controller.actions.zoomViewport(controller, 0.8));
  dom.zoomFit.addEventListener("click", () => controller.actions.resetViewport(controller));
  dom.focusExit.addEventListener("click", () => controller.actions.exitFocusMode(controller));
  dom.themeSelect.addEventListener("change", () =>
    controller.actions.applyTheme(controller, dom.themeSelect.value as Theme),
  );
}

function wirePathControls(controller: Controller): void {
  const { dom } = controller;
  dom.pathExit.addEventListener("click", () => {
    controller.actions.resetPath(controller);
    controller.actions.updateVisibility(controller);
  });
  dom.pathRun.addEventListener("click", () => runPath(controller));
  dom.pathReset.addEventListener("click", () => {
    controller.actions.resetPath(controller);
    controller.actions.updateVisibility(controller);
  });
}

function wireInspectorControls(controller: Controller): void {
  const { dom } = controller;
  dom.inspectorClose.addEventListener("click", () => controller.actions.closeInspector(controller));
  dom.resultsClose.addEventListener("click", () => controller.actions.closeResults(controller));
}

function wireQueryControls(controller: Controller): void {
  const { dom } = controller;
  dom.runCypher.addEventListener("click", () => void runCustomCypher(controller));
  dom.cypherInput.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
      event.preventDefault();
      void runCustomCypher(controller);
    }
  });
  dom.cypherHistory.addEventListener("change", () => {
    if (dom.cypherHistory.value) dom.cypherInput.value = dom.cypherHistory.value;
  });
  dom.clearHistory.addEventListener("click", () => {
    localStorage.removeItem(HISTORY_STORAGE_NAME);
    renderHistory(controller, []);
    controller.actions.setLiveStatus(controller, "Local Cypher history cleared.", "ok");
  });
}

function wireLiveControls(controller: Controller): void {
  const { dom } = controller;
  dom.liveRefresh.addEventListener("click", () => void liveRefresh(controller));
  dom.liveTier.addEventListener("click", () => void liveTierClassify(controller));
  dom.liveOwned.addEventListener("click", () => void liveShowOwned(controller));
  dom.connectionForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const token = dom.apiToken.value.trim();
    if (!token) return;
    setApiToken(token);
    dom.apiToken.value = "";
    startLiveSession(controller);
  });
}

function folioIsVisible(): boolean {
  return (
    document.body.classList.contains("folio-enabled") &&
    !document.body.classList.contains("graph-tools-open")
  );
}
export function wireKeyboardShortcuts(controller: Controller, dom: ViewerDom): void {
  document.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      document
        .querySelector<HTMLButtonElement>(
          "body.folio-enabled:not(.graph-tools-open) .folio-topbar button",
        )
        ?.click();
      dom.search.focus();
      dom.search.select();
      return;
    }
    if (folioIsVisible()) return;
    if (editableTarget(event.target)) return;
    shortcutAction(controller, dom, event.key)?.();
  });
}

export function editableTarget(target: EventTarget | null): boolean {
  return (
    target instanceof HTMLInputElement ||
    target instanceof HTMLTextAreaElement ||
    target instanceof HTMLSelectElement
  );
}

export function shortcutAction(
  controller: Controller,
  dom: ViewerDom,
  key: string,
): (() => void) | null {
  const actions: Record<string, () => void> = {
    escape: () => dismissTransientUi(controller),
    p: () => controller.actions.transitionWorkspace(controller, "paths", true),
    l: () => dom.labels.click(),
    a: () => dom.attack.click(),
    r: () => controller.actions.resetViewport(controller),
  };
  return actions[key.toLowerCase()] ?? null;
}

export function dismissTransientUi(controller: Controller): void {
  controller.actions.resetPath(controller);
  controller.actions.exitFocusMode(controller);
  controller.actions.closeInspector(controller);
}
