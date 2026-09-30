/** Renders the node dossier inspector: summary, tabs, evidence, relations, and remediation. */

import { toggleOwned } from "./live";
import { element, propertyValue } from "./runtime";
import type { Controller } from "./runtime";
import type { NodeId, ViewerNode } from "./types";
import { renderNodeList } from "./view";

export function inspectNode(controller: Controller, nodeId: NodeId): void {
  const node = controller.state.graph.nodeById.get(nodeId) ?? null;
  if (!node) return;
  prepareInspector(controller, nodeId);
  const summary = inspectorSummary(node);
  const actions = inspectorActions(controller, node);
  const properties = inspectorProperties(node);
  const relationships = relationshipPanel(controller, node.id);
  const provenance = provenancePanel(controller);
  const remediation = remediationPanel(controller, node.id);
  const panels = [properties, relationships, provenance, remediation];
  const tabs = inspectorTabs(...panels);

  const modelNote = element("p", {
    class: "model-note evidence-caveat",
    text: "Modeled preconditions do not prove exploitation.",
  });

  const footer = inspectorFooter(tabs, panels, properties);

  controller.dom.inspectorBody.append(
    summary,
    actions,
    tabs,
    properties,
    relationships,
    provenance,
    remediation,
    modelNote,
    footer,
  );
  controller.dom.inspector.classList.add("open");
  controller.dom.detailEmpty.hidden = true;
  renderNodeList(controller);
  controller.actions.markDirty(controller);
}

function prepareInspector(controller: Controller, nodeId: NodeId): void {
  controller.state.selection.selectedId = nodeId;
  controller.state.selection.pinnedId = nodeId;
  controller.dom.resultsPanel.classList.remove("open");
  controller.dom.inspectorBody.textContent = "";
}

function inspectorSummary(node: ViewerNode): HTMLElement {
  const risk = nodeRisk(node);
  const kindLabel = displayNodeKind(node.kind);
  const shortId = node.id.length <= 40 ? node.id : "";
  const subtitle = shortId ? `${kindLabel} · ${shortId}` : kindLabel;
  return element("div", { class: "inspector-summary" }, [
    summaryKicker(kindLabel, propertyText(node.properties.tier ?? node.properties.security_tier)),
    element("h3", { text: node.label ?? node.id }),
    element("p", { class: "field-help", text: subtitle }),
    summaryRiskLine(risk, propertyText(node.properties.risk_score ?? node.properties.score)),
  ]);
}

function propertyText(value: unknown): string {
  return typeof value === "string" || typeof value === "number" ? String(value) : "";
}

function summaryKicker(kindLabel: string, tier: string): HTMLElement {
  const kicker = element("div", { class: "inspector-kicker-row" }, [
    element("span", { class: "inspector-kicker", text: kindLabel }),
  ]);
  if (tier)
    kicker.appendChild(
      element("span", { class: "tier-chip", text: /^tier/i.test(tier) ? tier : `Tier ${tier}` }),
    );
  return kicker;
}

function summaryRiskLine(risk: string, score: string): HTMLElement {
  const riskLine = element("div", { class: "inspector-risk-line" }, [
    element("span", {
      class: `severity-badge ${risk}`,
      text: risk.charAt(0).toUpperCase() + risk.slice(1),
    }),
  ]);
  if (score)
    riskLine.appendChild(element("span", { class: "risk-score", text: `Risk ${score} / 10` }));
  return riskLine;
}

function inspectorActions(controller: Controller, node: ViewerNode): HTMLElement {
  const actions = element("div", { class: "inspector-actions" });
  const focus = element("button", { type: "button", class: "secondary-action", text: "Center" });
  focus.addEventListener("click", () => controller.actions.enterFocusMode(controller, node.id));
  const graph = element("button", {
    type: "button",
    class: "secondary-action",
    text: "Inspect in graph",
  });
  graph.addEventListener("click", () =>
    controller.actions.transitionWorkspace(controller, "graph", true),
  );
  const path = element("button", {
    type: "button",
    class: "secondary-action",
    text: "Find paths from here",
  });
  path.addEventListener("click", () => controller.actions.togglePathMode(controller, node.id));
  actions.append(focus, graph, path);
  if (controller.state.live.enabled) actions.appendChild(ownedAction(controller, node));
  return actions;
}

function ownedAction(controller: Controller, node: ViewerNode): HTMLButtonElement {
  const owned = element("button", {
    type: "button",
    class: "primary-action mark-owned",
    text: node.properties.owned === true ? "Clear owned" : "Mark owned",
  });
  owned.addEventListener("click", () => void toggleOwned(controller, node.id));
  return owned;
}

function inspectorProperties(node: ViewerNode): HTMLElement {
  const properties = element("section", {
    class: "prop-section inspector-panel",
    role: "tabpanel",
    "data-inspector-panel": "evidence",
  });
  for (const [key, value] of Object.entries(node.properties)
    .filter(([entryKey]) => !entryKey.startsWith("_"))
    .sort(([left], [right]) => left.localeCompare(right))) {
    properties.appendChild(
      element("div", { class: "prop-row" }, [
        element("span", { class: "prop-key", text: displayPropertyKey(key) }),
        element("span", { class: "prop-val", text: propertyValue(value) }),
      ]),
    );
  }
  return properties;
}

function inspectorFooter(
  tabs: HTMLElement,
  panels: HTMLElement[],
  properties: HTMLElement,
): HTMLElement {
  const raw = element("button", {
    type: "button",
    class: "text-button raw-evidence",
    text: "Raw fields",
  });
  raw.addEventListener("click", () => {
    selectInspectorPanel(tabs, panels, "evidence");
    properties.scrollIntoView({ block: "start", behavior: "smooth" });
  });
  return element("div", { class: "inspector-footer" }, [raw]);
}

export function displayNodeKind(kind: string): string {
  return kind.replace(/^rs_/, "").replace(/([a-z])([A-Z])/g, "$1 $2");
}

export function displayPropertyKey(key: string): string {
  return key
    .replace(/^_/, "")
    .replaceAll("_", " ")
    .replace(/^./, (character) => character.toUpperCase());
}

export function nodeRisk(node: ViewerNode): string {
  const risk = node.properties.risk_level ?? node.properties.severity;
  return typeof risk === "string" &&
    ["critical", "high", "medium", "low"].includes(risk.toLowerCase())
    ? risk.toLowerCase()
    : "informational";
}

export function inspectorTabs(...panels: HTMLElement[]): HTMLDivElement {
  const defs = [
    { id: "evidence", label: "Evidence" },
    { id: "relationships", label: "Relations" },
    { id: "provenance", label: "Provenance" },
    { id: "remediation", label: "Remediation" },
  ] as const;
  const tabs = element("div", {
    class: "inspector-tabs",
    role: "tablist",
    "aria-label": "Node details",
  });
  for (const [index, def] of defs.entries()) {
    const tab = element("button", {
      type: "button",
      role: "tab",
      "data-inspector-tab": def.id,
      "aria-selected": String(index === 0),
      text: def.label,
    });
    tab.addEventListener("click", () => selectInspectorPanel(tabs, panels, def.id));
    tabs.appendChild(tab);
  }
  return tabs;
}

export function selectInspectorPanel(
  tabs: HTMLElement,
  panels: HTMLElement[],
  active: string,
): void {
  for (const tab of tabs.querySelectorAll<HTMLElement>("[data-inspector-tab]")) {
    tab.setAttribute("aria-selected", String(tab.dataset.inspectorTab === active));
  }
  for (const panel of panels) panel.hidden = panel.dataset.inspectorPanel !== active;
}

export function relationshipPanel(controller: Controller, nodeId: NodeId): HTMLElement {
  const panel = inspectorPanel("relationships");
  panel.appendChild(element("h4", { text: "Relationship summary" }));
  const incoming = controller.state.graph.incoming.get(nodeId) ?? [];
  const outgoing = controller.state.graph.outgoing.get(nodeId) ?? [];
  panel.append(
    relationshipSummaryRow("Incoming", incoming.length),
    relationshipSummaryRow("Outgoing", outgoing.length),
    relationshipSummaryRow(
      "Connected",
      new Set([...incoming.map((entry) => entry.source), ...outgoing.map((entry) => entry.target)])
        .size,
    ),
  );
  for (const entry of incoming.slice(0, 8))
    panel.appendChild(relationshipDetail("From", entry.edge.kind, entry.source));
  for (const entry of outgoing.slice(0, 8))
    panel.appendChild(relationshipDetail("To", entry.edge.kind, entry.target));
  return panel;
}

export function relationshipSummaryRow(label: string, count: number): HTMLElement {
  return element("div", { class: "relationship-summary-row" }, [
    element("span", { text: label }),
    element("strong", { text: String(count) }),
  ]);
}

export function relationshipDetail(direction: string, kind: string, nodeId: string): HTMLElement {
  return element("div", { class: "relationship-detail" }, [
    element("span", { text: direction }),
    element("strong", { text: displayNodeKind(kind) }),
    element("code", { text: nodeId }),
  ]);
}

function connectedRecommendations(controller: Controller, nodeId: NodeId): ViewerNode[] {
  const adjacent = [
    ...(controller.state.graph.incoming.get(nodeId) ?? []).map((entry) => entry.source),
    ...(controller.state.graph.outgoing.get(nodeId) ?? []).map((entry) => entry.target),
  ];
  return adjacent
    .map((id) => controller.state.graph.nodeById.get(id))
    .filter(
      (candidate): candidate is ViewerNode =>
        candidate !== undefined && /recommendation/i.test(candidate.kind),
    );
}

export function remediationPanel(controller: Controller, nodeId: NodeId): HTMLElement {
  const panel = inspectorPanel("remediation");
  const connected = connectedRecommendations(controller, nodeId);
  appendEmptyRecommendationState(panel, connected.length);
  appendRecommendations(panel, connected);
  return panel;
}

export function provenancePanel(controller: Controller): HTMLElement {
  const panel = inspectorPanel("provenance");
  panel.appendChild(provenanceChain(controller));
  return panel;
}

function inspectorPanel(name: string): HTMLElement {
  const panel = element("section", {
    class: "prop-section inspector-panel",
    role: "tabpanel",
    "data-inspector-panel": name,
  });
  panel.hidden = true;
  return panel;
}

function appendEmptyRecommendationState(panel: HTMLElement, count: number): void {
  if (count === 0) {
    panel.appendChild(
      element("p", {
        class: "empty-state compact",
        text: "No connected recommendation is present in this graph snapshot.",
      }),
    );
  }
}

function appendRecommendations(panel: HTMLElement, connected: ViewerNode[]): void {
  for (const recommendation of connected) {
    panel.appendChild(
      element("div", { class: "recommendation-card" }, [
        element("span", { class: "recommendation-marker", "aria-hidden": "true" }),
        element("div", {}, [
          element("strong", { text: recommendation.label ?? recommendation.id }),
          element("p", { class: "field-help", text: "Graph recommendation" }),
        ]),
      ]),
    );
  }
}

export function provenanceChain(controller: Controller): HTMLElement {
  const metadata = controller.state.graph.payload.metadata ?? {};
  const section = element("section", { class: "prop-section provenance-chain" });
  section.appendChild(element("h4", { text: "Provenance chain" }));
  for (const [label, key] of [
    ["Collected", "collected_at"],
    ["Imported", "imported_at"],
    ["Derived", "derived_at"],
    ["Snapshot", "generated_at"],
  ] as const) {
    const value = typeof metadata[key] === "string" ? metadata[key] : "Not recorded";
    section.appendChild(
      element("div", { class: "provenance-row" }, [
        element("span", { "aria-hidden": "true", text: "⊙" }),
        element("strong", { text: label }),
        element("code", { text: value }),
      ]),
    );
  }
  return section;
}
