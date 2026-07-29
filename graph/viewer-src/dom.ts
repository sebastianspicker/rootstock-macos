/** Defines and collects the required DOM surface exposed by the viewer template. */

export interface ViewerDom {
  app: HTMLDivElement;
  metaInfo: HTMLParagraphElement;
  connectionStatus: HTMLSpanElement;
  provenanceStatus: HTMLElement;
  snapshotTime: HTMLElement;
  connectionGate: HTMLElement;
  connectionForm: HTMLFormElement;
  apiToken: HTMLInputElement;
  connectionError: HTMLParagraphElement;
  nodeCount: HTMLElement;
  edgeCount: HTMLElement;
  themeSelect: HTMLSelectElement;
  navOverview: HTMLButtonElement;
  navPaths: HTMLButtonElement;
  navGraph: HTMLButtonElement;
  navQueries: HTMLButtonElement;
  navExports: HTMLButtonElement;
  navSettings: HTMLButtonElement;
  tabExplore: HTMLButtonElement;
  tabQueries: HTMLButtonElement;
  explorePanel: HTMLElement;
  queriesPanel: HTMLElement;
  search: HTMLInputElement;
  clearSearch: HTMLButtonElement;
  searchStatus: HTMLParagraphElement;
  riskSummary: HTMLDivElement;
  evidenceCoverage: HTMLElement;
  evidenceCoverageBar: HTMLElement;
  nodeFilters: HTMLDivElement;
  edgeFilters: HTMLDivElement;
  clearFilters: HTMLButtonElement;
  nodeList: HTMLUListElement;
  nodeListCount: HTMLElement;
  nodeListEmpty: HTMLParagraphElement;
  queryList: HTMLDivElement;
  customQuerySection: HTMLElement;
  cypherInput: HTMLTextAreaElement;
  cypherHistory: HTMLSelectElement;
  runCypher: HTMLButtonElement;
  clearHistory: HTMLButtonElement;
  liveActions: HTMLDivElement;
  liveRefresh: HTMLButtonElement;
  liveTier: HTMLButtonElement;
  liveOwned: HTMLButtonElement;
  graphContainer: HTMLElement;
  canvas: HTMLCanvasElement;
  context: CanvasRenderingContext2D;
  tooltip: HTMLDivElement;
  focusBanner: HTMLDivElement;
  focusText: HTMLSpanElement;
  focusExit: HTMLButtonElement;
  pathBanner: HTMLDivElement;
  pathText: HTMLSpanElement;
  pathExit: HTMLButtonElement;
  contextMenu: HTMLDivElement;
  reset: HTMLButtonElement;
  labels: HTMLButtonElement;
  cluster: HTMLButtonElement;
  attack: HTMLButtonElement;
  path: HTMLButtonElement;
  vulnerable: HTMLButtonElement;
  exportPng: HTMLButtonElement;
  zoomIn: HTMLButtonElement;
  zoomOut: HTMLButtonElement;
  zoomFit: HTMLButtonElement;
  stats: HTMLDivElement;
  resultsPanel: HTMLElement;
  resultsTitle: HTMLElement;
  resultsMeta: HTMLDivElement;
  resultsBody: HTMLDivElement;
  resultsClose: HTMLButtonElement;
  inspector: HTMLElement;
  inspectorBody: HTMLDivElement;
  inspectorClose: HTMLButtonElement;
  detailEmpty: HTMLElement;
  timelineCollected: HTMLElement;
  timelineImported: HTMLElement;
  timelineDerived: HTMLElement;
  timelineSnapshot: HTMLElement;
  provenanceSource: HTMLElement;
  liveStatus: HTMLDivElement;
}

export function required<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) throw new Error(`Viewer template is missing #${id}`);
  return element as T;
}

export function collectDom(): ViewerDom {
  const canvas = required<HTMLCanvasElement>("graph-canvas");
  const context = canvas.getContext("2d");
  if (!context) throw new Error("Canvas 2D rendering is unavailable");
  return {
    app: required("app"), metaInfo: required("meta-info"), connectionStatus: required("connection-status"),
    provenanceStatus: required("provenance-status"),
    snapshotTime: required("snapshot-time"),
    connectionGate: required("connection-gate"), connectionForm: required("connection-form"),
    apiToken: required("api-token"), connectionError: required("connection-error"),
    nodeCount: required("node-count"), edgeCount: required("edge-count"), themeSelect: required("theme-select"),
    navOverview: required("nav-overview"), navPaths: required("nav-paths"),
    navGraph: required("nav-graph"), navQueries: required("nav-queries"),
    navExports: required("nav-exports"), navSettings: required("nav-settings"),
    tabExplore: required("tab-explore"), tabQueries: required("tab-queries"), explorePanel: required("explore-panel"),
    queriesPanel: required("queries-panel"), search: required("search"), clearSearch: required("clear-search"),
    searchStatus: required("search-status"), riskSummary: required("risk-summary"),
    evidenceCoverage: required("evidence-coverage"), evidenceCoverageBar: required("evidence-coverage-bar"),
    nodeFilters: required("node-filters"),
    edgeFilters: required("edge-filters"), clearFilters: required("clear-filters"), nodeList: required("node-list"),
    nodeListCount: required("node-list-count"), nodeListEmpty: required("node-list-empty"), queryList: required("query-list"),
    customQuerySection: required("custom-query-section"), cypherInput: required("cypher-input"),
    cypherHistory: required("cypher-history-select"), runCypher: required("run-cypher"), clearHistory: required("clear-history"),
    liveActions: required("live-actions"), liveRefresh: required("live-refresh"), liveTier: required("live-tier"),
    liveOwned: required("live-owned"), graphContainer: required("graph-container"), canvas, context, tooltip: required("tooltip"),
    focusBanner: required("focus-banner"), focusText: required("focus-text"), focusExit: required("focus-exit"),
    pathBanner: required("path-banner"), pathText: required("path-text"), pathExit: required("path-exit"),
    contextMenu: required("context-menu"), reset: required("btn-reset"), labels: required("btn-labels"),
    cluster: required("btn-cluster"), attack: required("btn-attack"), path: required("btn-path"), vulnerable: required("btn-vuln"),
    exportPng: required("btn-export"), zoomIn: required("btn-zoom-in"), zoomOut: required("btn-zoom-out"),
    zoomFit: required("btn-zoom-fit"), stats: required("stats"), resultsPanel: required("results-panel"),
    resultsTitle: required("results-title"), resultsMeta: required("results-meta"), resultsBody: required("results-body"),
    resultsClose: required("results-close"), inspector: required("inspector"), inspectorBody: required("inspector-body"),
    inspectorClose: required("inspector-close"), detailEmpty: required("detail-empty"),
    timelineCollected: required("timeline-collected"), timelineImported: required("timeline-imported"),
    timelineDerived: required("timeline-derived"), timelineSnapshot: required("timeline-snapshot"),
    provenanceSource: required("provenance-source"), liveStatus: required("live-status"),
  };
}
