/** Builds the deterministic, evidence-first triage queue. */

import { element } from "./runtime";
import { riskLabel } from "./view";
import { edgeIsInferred } from "./canvas-edges";
import type { Controller } from "./runtime";
import type { ViewerNode } from "./types";

const severityRank: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
  unknown: 5,
};

function numericRisk(node: ViewerNode): number {
  const value = node.properties.risk_score;
  return typeof value === "number" && Number.isFinite(value) ? value : Number.NEGATIVE_INFINITY;
}

function severity(node: ViewerNode): string {
  const value = riskLabel(node.properties.risk_level ?? node.properties.severity);
  return severityRank[value] === undefined ? "unknown" : value;
}

function rank(node: ViewerNode): number {
  return severityRank[severity(node)] ?? severityRank.unknown ?? 5;
}

export function triageNodes(controller: Controller): ViewerNode[] {
  return [...controller.state.graph.nodes].sort(
    (left, right) =>
      numericRisk(right) - numericRisk(left) ||
      rank(left) - rank(right) ||
      (left.label ?? left.id).localeCompare(right.label ?? right.id) ||
      left.id.localeCompare(right.id),
  );
}

const SECTIONS = ["critical", "high", "medium", "low", "informational"] as const;
const showUnscored = new WeakMap<Controller, boolean>();

function sectionTitle(level: string): string {
  return level === "unknown" ? "Unscored" : `${level.charAt(0).toUpperCase()}${level.slice(1)}`;
}

function inferredIncoming(controller: Controller, node: ViewerNode): number {
  return (controller.state.graph.incoming.get(node.id) ?? []).filter((entry) =>
    edgeIsInferred(entry.edge),
  ).length;
}

/** `risk 7 · 2 inferred relationships in · role`, omitting parts that are absent. */
export function triageMeta(controller: Controller, node: ViewerNode): string {
  const score = numericRisk(node);
  const parts = [score === Number.NEGATIVE_INFINITY ? "risk unavailable" : `risk ${score}`];
  const inferred = inferredIncoming(controller, node);
  if (inferred > 0)
    parts.push(`${inferred} inferred ${inferred === 1 ? "relationship" : "relationships"} in`);
  if (typeof node.properties.modeled_role === "string") parts.push(node.properties.modeled_role);
  return parts.join(" · ");
}

function triageItem(controller: Controller, node: ViewerNode): HTMLLIElement {
  const label = node.label ?? node.id;
  const dossier = element(
    "button",
    { type: "button", class: "triage-row", "data-node-id": node.id },
    [
      element("span", {
        class: `node-symbol node-severity-${severity(node) === "unknown" ? "informational" : severity(node)}`,
        "aria-hidden": "true",
      }),
      element("span", { class: "triage-label", text: label }),
      element("span", { class: "triage-meta", text: triageMeta(controller, node) }),
      element("span", { class: "triage-kind", text: node.kind.replace(/^rs_/, "") }),
    ],
  );
  dossier.addEventListener("click", () => {
    controller.actions.inspectNode(controller, node.id);
    controller.actions.revealNode(controller, node.id);
  });
  const inspect = element("button", {
    type: "button",
    class: "secondary-action triage-inspect",
    "aria-label": `Inspect ${label} in graph`,
    text: "Inspect in graph",
  });
  inspect.addEventListener("click", () => {
    controller.actions.transitionWorkspace(controller, "graph", true);
    controller.actions.inspectNode(controller, node.id);
    controller.actions.revealNode(controller, node.id);
  });
  return element("li", { class: "triage-item" }, [dossier, inspect]);
}

function triageSection(level: string, count: number): HTMLLIElement {
  return element("li", {
    class: `triage-section ${level}`,
    role: "presentation",
    text: `${sectionTitle(level)} · ${count}`,
  });
}

function renderUnscoredToggle(controller: Controller, count: number, shown: boolean): void {
  const toggle = controller.dom.triageUnscored;
  toggle.hidden = count === 0;
  toggle.textContent = `${shown ? "Hide" : "Show"} ${count} ${count === 1 ? "node" : "nodes"} without a severity`;
  toggle.setAttribute("aria-pressed", String(shown));
  toggle.onclick = () => {
    showUnscored.set(controller, !shown);
    renderTriageQueue(controller);
  };
}

function emptyMessage(controller: Controller, total: number): string {
  if (total === 0) return "No findings are available in this snapshot.";
  return controller.state.live.enabled
    ? "No node in this snapshot carries a severity. Run rootstock-graph-infer and refresh to score risk."
    : "No node in this snapshot carries a severity. Run rootstock-graph-infer and export a new snapshot to score risk.";
}

/** Groups the queue under severity headings; unscored nodes wait behind an explicit toggle. */
export function renderTriageQueue(controller: Controller): void {
  const { triageList, triageEmpty } = controller.dom;
  const nodes = triageNodes(controller);
  const unscored = nodes.filter((node) => severity(node) === "unknown");
  const shown = showUnscored.get(controller) === true;
  triageList.replaceChildren();
  triageEmpty.hidden = unscored.length !== nodes.length;
  triageEmpty.textContent = emptyMessage(controller, nodes.length);
  renderUnscoredToggle(controller, unscored.length, shown);
  const levels: string[] = shown ? [...SECTIONS, "unknown"] : [...SECTIONS];
  for (const level of levels) {
    const members = nodes.filter((node) => severity(node) === level);
    if (members.length === 0) continue;
    triageList.appendChild(triageSection(level, members.length));
    for (const node of members) triageList.appendChild(triageItem(controller, node));
  }
}
