/** Builds the deterministic, evidence-first triage queue. */

import { element } from "./runtime";
import { riskLabel } from "./view";
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

export function renderTriageQueue(controller: Controller): void {
  const { triageList, triageEmpty } = controller.dom;
  const nodes = triageNodes(controller);
  triageList.replaceChildren();
  triageEmpty.hidden = nodes.length !== 0;
  for (const node of nodes) {
    const level = severity(node);
    const score = numericRisk(node);
    const dossier = element(
      "button",
      { type: "button", class: "triage-row", "data-node-id": node.id },
      [
        element("span", { class: `node-symbol node-severity-${level}`, "aria-hidden": "true" }),
        element("span", { class: "triage-label", text: node.label ?? node.id }),
        element("span", {
          class: "triage-meta",
          text: `${level} · ${score === Number.NEGATIVE_INFINITY ? "risk unavailable" : `risk ${score}`}`,
        }),
        element("span", { class: "triage-kind", text: node.kind.replace(/^rs_/, "") }),
      ],
    );
    dossier.addEventListener("click", () => controller.actions.inspectNode(controller, node.id));
    const inspect = element("button", {
      type: "button",
      class: "secondary-action triage-inspect",
      text: "Inspect in graph",
    });
    inspect.addEventListener("click", () => {
      controller.actions.transitionWorkspace(controller, "graph", true);
      controller.actions.inspectNode(controller, node.id);
    });
    triageList.appendChild(element("li", { class: "triage-item" }, [dossier, inspect]));
  }
}
