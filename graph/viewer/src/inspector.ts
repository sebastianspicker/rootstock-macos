/** Renders the node dossier inspector: summary, tabs, evidence, relations, and remediation. */

import { toggleOwned } from "./live";
import { nodeKindDescription } from "./glossary";
import { displayKind } from "./model";
import { element, propertyValue } from "./runtime";
import type { Controller } from "./runtime";
import type { NodeId, ViewerNode } from "./types";
import { renderNodeList } from "./view";
import { relationshipPanel } from "./inspector-relations";
import { factPropertyKeys, keyFacts } from "./inspector-facts";
export {
  relationshipPanel,
  relationshipSummaryRow,
  relationshipDetail,
} from "./inspector-relations";

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

  // DOM order matches the visual order so reading and tab order follow the layout.
  controller.dom.inspectorBody.append(
    summary,
    tabs,
    properties,
    relationships,
    provenance,
    remediation,
    actions,
    modelNote,
    footer,
  );
  controller.dom.inspectorAnnouncer.textContent = `Details for ${node.label ?? node.id}`;
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
  const about = nodeKindDescription(node.kind);
  const children = [
    summaryKicker(kindLabel, propertyText(node.properties.tier ?? node.properties.security_tier)),
    element("h3", { text: node.label ?? node.id }),
    element("p", { class: "field-help", text: subtitle }),
    summaryRiskLine(
      risk,
      propertyText(node.properties.risk_score ?? node.properties.score),
      node.properties.owned === true,
    ),
  ];
  if (about) children.push(element("p", { class: "inspector-about field-help", text: about }));
  return element("div", { class: "inspector-summary" }, children);
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

function summaryRiskLine(risk: string, score: string, owned: boolean): HTMLElement {
  const riskLine = element("div", { class: "inspector-risk-line" }, [
    element("span", {
      class: `severity-badge ${risk}`,
      text: risk.charAt(0).toUpperCase() + risk.slice(1),
    }),
  ]);
  if (score)
    riskLine.appendChild(element("span", { class: "risk-score", text: `Risk ${score} / 10` }));
  if (owned) riskLine.appendChild(element("span", { class: "owned-chip", text: "owned" }));
  return riskLine;
}

function inspectorActions(controller: Controller, node: ViewerNode): HTMLElement {
  const actions = element("div", { class: "inspector-actions" });
  if (controller.state.live.enabled) actions.appendChild(ownedAction(controller, node));
  const center = element("button", { type: "button", class: "secondary-action", text: "Center" });
  center.addEventListener("click", () => controller.actions.centerNode(controller, node.id));
  const focus = element("button", {
    type: "button",
    class: "secondary-action",
    text: "Neighbors only",
  });
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
  actions.append(center, focus, graph, path);
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

/** Properties rendered as their own lists above the raw rows. */
const LISTED_PROPERTIES = new Set(["risk_reasons", "posture_findings", "posture_unknown"]);

function stringList(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string" && item !== "")
    : [];
}

function listSection(title: string, items: string[], className: string): HTMLElement[] {
  return [
    element("h4", { text: title }),
    element(
      "ul",
      { class: className },
      items.map((item) => element("li", { text: item })),
    ),
  ];
}

/** "Why this score", and for the Computer node the host findings and uncollected settings. */
export function evidenceExplanations(node: ViewerNode): HTMLElement[] {
  const reasons = stringList(node.properties.risk_reasons);
  const sections = reasons.length ? listSection("Why this score", reasons, "risk-reasons") : [];
  if (node.kind !== "rs_Computer") return sections;
  const findings = stringList(node.properties.posture_findings);
  const unknown = stringList(node.properties.posture_unknown);
  sections.push(
    ...(findings.length
      ? listSection("Host findings", findings, "risk-reasons")
      : [
          element("h4", { text: "Host findings" }),
          element("p", {
            class: "field-help",
            text: "No definite weaknesses in the collected settings.",
          }),
        ]),
  );
  if (unknown.length) sections.push(...listSection("Not collected", unknown, "gap-list"));
  return sections;
}

function propertyRowValue(key: string, value: unknown): string {
  return key === "collection_error_sources" && Array.isArray(value)
    ? stringList(value).join(", ")
    : propertyValue(value);
}

function inspectorProperties(node: ViewerNode): HTMLElement {
  const properties = element("section", {
    class: "prop-section inspector-panel",
    role: "tabpanel",
    "data-inspector-panel": "evidence",
  });
  const facts = keyFacts(node);
  properties.append(...evidenceExplanations(node), ...facts);
  if (facts.length) properties.appendChild(element("h4", { text: "Other recorded fields" }));
  const shown = factPropertyKeys(node.kind);
  for (const [key, value] of Object.entries(node.properties)
    .filter(
      ([entryKey]) =>
        !entryKey.startsWith("_") && !LISTED_PROPERTIES.has(entryKey) && !shown.has(entryKey),
    )
    .sort(([left], [right]) => left.localeCompare(right))) {
    properties.appendChild(
      element("div", { class: "prop-row" }, [
        element("span", { class: "prop-key", text: displayPropertyKey(key) }),
        element("span", { class: "prop-val", text: propertyRowValue(key, value) }),
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
    properties.scrollIntoView({ block: "start", behavior: scrollBehavior() });
  });
  return element("div", { class: "inspector-footer" }, [raw]);
}

export function scrollBehavior(): ScrollBehavior {
  return matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth";
}

export function displayNodeKind(kind: string): string {
  return displayKind(kind);
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
      id: `inspector-tab-${def.id}`,
      "aria-controls": `inspector-panel-${def.id}`,
      "data-inspector-tab": def.id,
      "aria-selected": String(index === 0),
      tabindex: index === 0 ? "0" : "-1",
      text: def.label,
    });
    tab.addEventListener("click", () => selectInspectorPanel(tabs, panels, def.id));
    tabs.appendChild(tab);
  }
  for (const panel of panels) {
    const id = panel.dataset.inspectorPanel ?? "";
    panel.id = `inspector-panel-${id}`;
    panel.setAttribute("aria-labelledby", `inspector-tab-${id}`);
  }
  tabs.addEventListener("keydown", (event) => moveInspectorTab(event, tabs, panels));
  return tabs;
}

/** Left and Right move between tabs with a roving tabindex; Home and End jump to the ends. */
function moveInspectorTab(event: KeyboardEvent, tabs: HTMLElement, panels: HTMLElement[]): void {
  const all = Array.from(tabs.querySelectorAll<HTMLButtonElement>("[data-inspector-tab]"));
  const current = all.indexOf(document.activeElement as HTMLButtonElement);
  if (current < 0) return;
  const offsets: Record<string, number> = { ArrowRight: 1, ArrowLeft: -1 };
  let next = current;
  if (event.key in offsets) next = (current + (offsets[event.key] ?? 0) + all.length) % all.length;
  else if (event.key === "Home") next = 0;
  else if (event.key === "End") next = all.length - 1;
  else return;
  event.preventDefault();
  const tab = all[next];
  if (!tab) return;
  selectInspectorPanel(tabs, panels, tab.dataset.inspectorTab ?? "evidence");
  tab.focus();
}

export function selectInspectorPanel(
  tabs: HTMLElement,
  panels: HTMLElement[],
  active: string,
): void {
  for (const tab of tabs.querySelectorAll<HTMLElement>("[data-inspector-tab]")) {
    const selected = tab.dataset.inspectorTab === active;
    tab.setAttribute("aria-selected", String(selected));
    tab.tabIndex = selected ? 0 : -1;
  }
  for (const panel of panels) panel.hidden = panel.dataset.inspectorPanel !== active;
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

export function inspectorPanel(name: string): HTMLElement {
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

function recommendationText(node: ViewerNode, key: string): string {
  const value = node.properties[key];
  return typeof value === "string" ? value : "";
}

function recommendationCard(recommendation: ViewerNode): HTMLElement {
  const title =
    recommendationText(recommendation, "title") || (recommendation.label ?? recommendation.id);
  const text = recommendationText(recommendation, "text");
  const priority = recommendationText(recommendation, "priority").toLowerCase();
  const heading: HTMLElement[] = [element("strong", { text: title })];
  if (priority)
    heading.push(
      element("span", {
        class: `folio-priority ${["critical", "high", "medium", "low"].includes(priority) ? priority : ""}`,
        text: priority,
      }),
    );
  const body = [element("div", { class: "recommendation-heading" }, heading)];
  body.push(
    element("p", {
      class: "field-help",
      text: text && text !== title ? text : "Graph recommendation",
    }),
  );
  return element("div", { class: "recommendation-card" }, [
    element("span", { class: "recommendation-marker", "aria-hidden": "true" }),
    element("div", {}, body),
  ]);
}

function appendRecommendations(panel: HTMLElement, connected: ViewerNode[]): void {
  for (const recommendation of connected) panel.appendChild(recommendationCard(recommendation));
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
