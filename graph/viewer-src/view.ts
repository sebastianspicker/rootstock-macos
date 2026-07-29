/** Renders graph metadata, filter controls, summaries, and inspector-facing DOM fragments. */

import {element} from "./runtime";
import {displayKind, safeNodeColor} from "./model";
import type {Controller} from "./runtime";

function renderMetadataSummary(controller: Controller, hostname: string, generatedAt: Date | null): void {
  controller.dom.metaInfo.textContent = hostname || "provenance unavailable";
  controller.dom.snapshotTime.textContent = displayTimestamp(generatedAt);
  controller.dom.nodeCount.textContent = String(controller.state.graph.nodes.length);
  controller.dom.edgeCount.textContent = String(controller.state.graph.links.length);
  controller.dom.provenanceSource.textContent = typeof controller.state.graph.payload.metadata?.source === "string"
    ? controller.state.graph.payload.metadata.source
    : hostname || "Unavailable";
}

function renderTimeline(controller: Controller, metadata: Record<string, unknown>, generatedAt: Date | null): void {
  controller.dom.timelineCollected.textContent = displayTimestamp(metadataTimestamp(metadata.collected_at));
  controller.dom.timelineImported.textContent = displayTimestamp(metadataTimestamp(metadata.imported_at));
  controller.dom.timelineDerived.textContent = displayTimestamp(metadataTimestamp(metadata.derived_at));
  controller.dom.timelineSnapshot.textContent = displayTimestamp(generatedAt);
}

function renderProvenanceStatus(controller: Controller, metadata: Record<string, unknown>): void {
  const recordedStages = ["collected_at", "imported_at", "derived_at", "generated_at"]
    .filter((stage) => metadataTimestamp(metadata[stage]) !== null).length;
  const status = recordedStages === 4 ? "Recorded" : recordedStages > 0 ? "Partial" : "Unavailable";
  controller.dom.provenanceStatus.textContent = status;
  controller.dom.provenanceStatus.dataset.state = status.toLowerCase();
}

export function renderMetadata(controller: Controller): void {
  const metadata = controller.state.graph.payload.metadata ?? {};
  const hostname = typeof metadata.hostname === "string" ? metadata.hostname : "";
  const generatedAt = metadataTimestamp(metadata.generated_at);
  renderMetadataSummary(controller, hostname, generatedAt);
  renderTimeline(controller, metadata, generatedAt);
  renderProvenanceStatus(controller, metadata);
}

export function metadataTimestamp(value: unknown): Date | null {
  if (typeof value !== "string" || value.length === 0) return null;
  const timestamp = new Date(value);
  return Number.isNaN(timestamp.valueOf()) ? null : timestamp;
}

export function displayTime(timestamp: Date): string {
  return timestamp.toLocaleTimeString([], {hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false});
}

export function displayTimestamp(timestamp: Date | null): string {
  return timestamp ? displayTime(timestamp) : "Not recorded";
}

export function renderRiskSummary(controller: Controller): void {
  const counts = riskCounts(controller);
  controller.dom.riskSummary.replaceChildren();
  for (const risk of ["critical", "high", "medium", "low"]) {
    controller.dom.riskSummary.appendChild(riskMetric(risk, counts.get(risk) ?? 0));
  }
  const coverage = evidenceCoverage(controller);
  controller.dom.evidenceCoverage.textContent = coverage === null ? "Unavailable" : `${coverage}%`;
  controller.dom.evidenceCoverageBar.style.width = `${coverage ?? 0}%`;
}

export function evidenceCoverage(controller: Controller): number | null {
  const {nodes} = controller.state.graph;
  if (nodes.length === 0) return null;
  const evidenced = nodes.filter((node) => {
    const evidence = node.properties.evidence ?? node.properties.source ?? node.properties.provenance;
    return typeof evidence === "string" ? evidence.trim().length > 0 : evidence !== null && evidence !== undefined;
  }).length;
  return Math.round((evidenced / nodes.length) * 100);
}

export function riskCounts(controller: Controller): Map<string, number> {
  const counts = new Map<string, number>();
  for (const node of controller.state.graph.nodes) addRiskCount(counts, riskLabel(node.properties.risk_level ?? node.properties.severity));
  return counts;
}

export function addRiskCount(counts: Map<string, number>, risk: string): void {
  if (risk) counts.set(risk, (counts.get(risk) ?? 0) + 1);
}

export function appendRiskChip(container: HTMLDivElement, risk: string, count: number): void {
  if (count > 0) container.appendChild(riskChip(risk, count));
}

export function riskLabel(value: unknown): string { return typeof value === "string" ? value.toLowerCase() : ""; }

export function nodeColor(node: Controller["state"]["graph"]["nodes"][number]): string {
  return safeNodeColor(node.properties._color);
}

export function riskChip(risk: string, count: number): HTMLSpanElement {
  return element("span", {class: `risk-chip ${risk}`}, [
    document.createTextNode(`${risk[0]?.toUpperCase()}${risk.slice(1)} `),
    element("span", {class: "chip-count", text: String(count)}),
  ]);
}

export function riskMetric(risk: string, count: number): HTMLDivElement {
  return element("div", {class: `risk-metric ${risk}`}, [
    element("strong", {text: String(count)}),
    element("span", {text: `${risk[0]?.toUpperCase()}${risk.slice(1)}`}),
  ]);
}

export function renderStats(controller: Controller): void {
  controller.dom.stats.replaceChildren(
    element("span", {class: "stat-item", text: `${controller.state.render.visibleNodeIds.size} visible nodes`} ),
    element("span", {class: "stat-item", text: `${controller.state.render.visibleLinkIndexes.size} visible edges`} ),
  );
}

export function renderNodeList(controller: Controller): void {
  const {state, dom} = controller;
  const visible = state.graph.nodes.filter((node) => state.render.visibleNodeIds.has(node.id))
    .sort((left, right) => (left.label ?? left.id).localeCompare(right.label ?? right.id));
  dom.nodeList.replaceChildren();
  dom.nodeListCount.textContent = `${visible.length}`;
  dom.nodeListEmpty.hidden = visible.length > 0;
  for (const node of visible) dom.nodeList.appendChild(nodeListItem(controller, node));
}

export function nodeListItem(controller: Controller, node: Controller["state"]["graph"]["nodes"][number]): HTMLLIElement {
  const button = element("button", {type: "button", class: "node-list-button", "data-node-id": node.id, "aria-current": String(controller.state.selection.selectedId === node.id)}, [
    element("span", {class: `node-symbol node-symbol-${nodeShapeClass(node.kind)}`, "aria-hidden": "true"}),
    element("span", {class: "node-list-label", text: node.label ?? node.id}),
    element("span", {class: "node-list-kind", text: displayKind(node.kind)}),
  ]);
  const dot = button.querySelector<HTMLElement>(".node-symbol");
  if (dot) dot.style.setProperty("--node-color", nodeColor(node));
  button.addEventListener("click", () => controller.actions.selectNode(controller, node.id));
  return element("li", {}, [button]);
}

export function nodeShapeClass(kind: string): string {
  if (/keychain|credential/i.test(kind)) return "key";
  if (/permission|tcc|file|configuration/i.test(kind)) return "shield";
  if (/launch|persistence/i.test(kind)) return "diamond";
  if (/recommendation|remediation/i.test(kind)) return "check";
  return "application";
}

export function buildFilters(controller: Controller): void {
  controller.dom.nodeFilters.replaceChildren(...nodeFilterItems(controller));
  controller.dom.edgeFilters.replaceChildren(...edgeFilterItems(controller));
}

export function nodeFilterItems(controller: Controller): HTMLLabelElement[] {
  return [...controller.state.graph.kindMeta.entries()].sort((left, right) => right[1].count - left[1].count)
    .map(([kind, info]) => filterItem(controller, kind, info.label, info.count, info.color, controller.state.filters.activeNodeKinds));
}

export function edgeFilterItems(controller: Controller): HTMLLabelElement[] {
  return [...controller.state.graph.edgeMeta.entries()].sort()
    .map(([kind, info]) => filterItem(controller, kind, info.label, info.count, null, controller.state.filters.activeEdgeKinds));
}

export function filterItem(controller: Controller, kind: string, label: string, count: number, color: string | null, activeKinds: Set<string>): HTMLLabelElement {
  const checkbox = element("input", {type: "checkbox"}) as HTMLInputElement;
  checkbox.checked = activeKinds.has(kind);
  checkbox.addEventListener("change", () => {
    if (checkbox.checked) activeKinds.add(kind); else activeKinds.delete(kind);
    controller.actions.updateVisibility(controller);
  });
  const children: Node[] = [checkbox];
  if (color) { const dot = element("span", {class: "color-dot"}); dot.style.background = color; children.push(dot); }
  children.push(element("span", {text: label}), element("span", {class: "filter-count", text: String(count)}));
  return element("label", {class: "filter-item"}, children);
}
