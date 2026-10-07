/** Inspector relationship tab: counts by basis and navigable incoming and outgoing rows. */

import { edgeIsInferred, edgeIsTraversable } from "./canvas-edges";
import { element } from "./runtime";
import type { Controller } from "./runtime";
import type { GraphEdge, NodeId } from "./types";

const RELATIONSHIP_LIMIT = 12;

function relationKind(kind: string): string {
  return kind.replace(/^rs_/, "").replace(/([a-z])([A-Z])/g, "$1 $2");
}

export function relationshipPanel(controller: Controller, nodeId: NodeId): HTMLElement {
  const panel = element("section", {
    class: "prop-section inspector-panel",
    role: "tabpanel",
    "data-inspector-panel": "relationships",
  });
  panel.hidden = true;
  panel.appendChild(element("h4", { text: "Relationship summary" }));
  const incoming = controller.state.graph.incoming.get(nodeId) ?? [];
  const outgoing = controller.state.graph.outgoing.get(nodeId) ?? [];
  const edges = [...incoming, ...outgoing].map((entry) => entry.edge);
  const inferred = edges.filter(edgeIsInferred).length;
  panel.append(
    relationshipSummaryRow("Incoming", incoming.length),
    relationshipSummaryRow("Outgoing", outgoing.length),
    relationshipSummaryRow(
      "Connected",
      new Set([...incoming.map((entry) => entry.source), ...outgoing.map((entry) => entry.target)])
        .size,
    ),
    element("div", { class: "relationship-summary-row" }, [
      element("span", { text: "Basis" }),
      element("strong", { text: `Observed ${edges.length - inferred} · Inferred ${inferred}` }),
    ]),
  );
  appendRelationships(
    controller,
    panel,
    "From",
    incoming.map((entry) => ({ edge: entry.edge, other: entry.source })),
  );
  appendRelationships(
    controller,
    panel,
    "To",
    outgoing.map((entry) => ({ edge: entry.edge, other: entry.target })),
  );
  return panel;
}

function appendRelationships(
  controller: Controller,
  panel: HTMLElement,
  direction: string,
  entries: { edge: GraphEdge; other: NodeId }[],
): void {
  for (const entry of entries.slice(0, RELATIONSHIP_LIMIT))
    panel.appendChild(relationshipDetail(controller, direction, entry.edge, entry.other));
  const hidden = entries.length - RELATIONSHIP_LIMIT;
  if (hidden > 0)
    panel.appendChild(
      element("p", {
        class: "relationship-more",
        text: `+${hidden} more ${direction === "From" ? "incoming" : "outgoing"}`,
      }),
    );
}

export function relationshipSummaryRow(label: string, count: number): HTMLElement {
  return element("div", { class: "relationship-summary-row" }, [
    element("span", { text: label }),
    element("strong", { text: String(count) }),
  ]);
}

/** One relationship: direction, kind, the other node as a link, its basis, and traversal. */
export function relationshipDetail(
  controller: Controller,
  direction: string,
  edge: GraphEdge,
  nodeId: NodeId,
): HTMLElement {
  const other = controller.state.graph.nodeById.get(nodeId);
  const link = element("button", { type: "button", class: "relationship-link" }, [
    element("span", { class: "relationship-link-label", text: other?.label ?? nodeId }),
    element("span", {
      class: "relationship-link-kind",
      text: other ? relationKind(other.kind) : "",
    }),
  ]);
  link.addEventListener("click", () => {
    controller.actions.revealNode(controller, nodeId);
    controller.actions.inspectNode(controller, nodeId);
    controller.dom.inspector.querySelector<HTMLElement>('[role="tab"]')?.focus();
  });
  const basis = edgeIsInferred(edge) ? "inferred" : "observed";
  const children: Node[] = [
    element("span", { class: "relationship-direction", text: direction }),
    element("strong", { text: relationKind(edge.kind) }),
    link,
    element("span", { class: `relationship-basis ${basis}`, text: basis }),
  ];
  if (!edgeIsTraversable(edge))
    children.push(element("span", { class: "relationship-note", text: "not traversable" }));
  return element("div", { class: `relationship-detail ${basis}` }, children);
}
