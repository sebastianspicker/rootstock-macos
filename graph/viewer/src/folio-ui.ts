/** Small semantic building blocks for the evidence document. Untrusted data is always text. */
import { element } from "./runtime";
import {
  value,
  nodeName,
  injectionEdges,
  fdaEdges,
  deniedFdaEdges,
  coverageText,
  edgeKindLabel,
  edgeBasis,
} from "./folio-data";
import type { Controller } from "./runtime";
import type { GraphEdge, GraphModel, Theme, ViewerNode } from "./types";
export const el = element;
export const para = (text: string, className = ""): HTMLParagraphElement =>
  el("p", { text, class: className });
export const heading = (text: string): HTMLHeadingElement => el("h2", { text });
export function button(text: string, action: () => void, primary = false): HTMLButtonElement {
  const control = el("button", {
    type: "button",
    text,
    class: primary ? "folio-primary" : "folio-button",
  });
  control.addEventListener("click", action);
  return control;
}
/** Name/value pairs; `label` sets them as the ruled specimen label for collection metadata. */
export function facts(rows: [string, string][], label = false): HTMLDListElement {
  return el(
    "dl",
    { class: label ? "folio-facts folio-label" : "folio-facts" },
    rows.flatMap(([name, content]) => [el("dt", { text: name }), el("dd", { text: content })]),
  );
}
/** Mirrors the Graph tools theme select so the folio can be read on paper or lightbox. */
export function themeControl(controller: Controller): HTMLElement {
  const shared = controller.dom.themeSelect;
  const select = el("select", { id: "folio-theme", class: "folio-theme" });
  for (const option of Array.from(shared.options))
    select.append(el("option", { value: option.value, text: option.text }));
  select.value = shared.value;
  select.addEventListener("change", () => {
    shared.value = select.value;
    controller.actions.applyTheme(controller, select.value as Theme);
  });
  return el("div", { class: "folio-theme-field" }, [
    el("label", { for: "folio-theme", class: "sr-only", text: "Theme" }),
    select,
  ]);
}
export function warning(graph: GraphModel): HTMLElement {
  return el("div", { class: "folio-warning", role: "note" }, [
    el("span", { text: "Gap", class: "folio-warning-mark", "aria-hidden": "true" }),
    para(coverageText(graph)),
  ]);
}
export function intro(title: string, text: string, sheet: string): HTMLElement {
  return el("header", { class: "folio-intro" }, [
    para(sheet, "folio-sheet"),
    el("h1", { text: title, tabindex: "-1" }),
    para(text, "folio-lead"),
  ]);
}
/** Marginal key to the folio's two inks: what was recorded versus what was modeled. */
export function conventions(): HTMLElement {
  return el("aside", { class: "folio-aside" }, [
    heading("Reading this folio"),
    conventionList(),
    para(
      "A modeled path is a chain of preconditions. It does not show that anything was exploited, and this viewer never changes host settings.",
      "folio-note",
    ),
  ]);
}
/** The three bases as a definition list; `compact` drops the descriptions for the margin. */
export function conventionList(compact = false): HTMLDListElement {
  const items = [
    ["observed", "Observed", "Recorded by the collector on this host. Set in ink on a solid rule."],
    [
      "inferred",
      "Inferred",
      "Modeled by Rootstock from observed facts. Set in pencil blue on a dashed rule.",
    ],
    ["unknown", "Unknown", "Not collected. Unknown is never read as false, or as safe."],
  ];
  return el(
    "dl",
    { class: compact ? "folio-conventions compact" : "folio-conventions" },
    items.flatMap(([kind, term, description]) => [
      el("dt", { class: `folio-mark ${kind ?? ""}`, text: term ?? "" }),
      el("dd", { text: compact ? (description?.split(". ")[0] ?? "") : (description ?? "") }),
    ]),
  );
}
export function appIdentity(node: ViewerNode): HTMLElement {
  return el("div", { class: "folio-identity" }, [
    heading(nodeName(node)),
    para(value(node.properties.bundle_id), "folio-code"),
    para(value(node.properties.path), "folio-code"),
  ]);
}
export function evidenceTable(graph: GraphModel, node: ViewerNode): HTMLElement {
  const observed = (key: string): string =>
    typeof node.properties[key] === "boolean" ? "observed" : "unknown";
  const bool = (key: string): string =>
    node.properties[key] === true
      ? "enabled"
      : node.properties[key] === false
        ? "disabled"
        : "Unknown";
  const allowed = fdaEdges(graph, node.id).length > 0;
  const denied = !allowed && deniedFdaEdges(graph, node.id).length > 0;
  const rows = [
    [
      "Full Disk Access grant",
      allowed ? "allowed" : denied ? "denied" : "Unknown",
      allowed || denied ? "observed" : "unknown",
    ],
    ["Hardened Runtime", bool("hardened_runtime"), observed("hardened_runtime")],
    ["Library Validation", bool("library_validation"), observed("library_validation")],
    ["SIP-protected", value(node.properties.is_sip_protected), observed("is_sip_protected")],
  ];
  return el("table", { class: "folio-table" }, [
    el("caption", { text: `Evidence for ${nodeName(node)}` }),
    el("thead", {}, [
      el(
        "tr",
        {},
        ["Evidence", "Value", "Basis"].map((text) => el("th", { scope: "col", text })),
      ),
    ]),
    el(
      "tbody",
      {},
      rows.map(([name, content, basis]) =>
        el("tr", {}, [
          el("th", { scope: "row", text: name ?? "" }),
          el("td", {}, [
            el("span", {
              text: content ?? "",
              class: `folio-tag ${["disabled", "false", "denied"].includes(content ?? "") ? "negative" : ""}`,
            }),
          ]),
          el("td", { text: basis ?? "", class: `folio-basis ${basis ?? ""}` }),
        ]),
      ),
    ),
  ]);
}
/** Q01 figure: the modeled injection, the application, and its Full Disk Access grant. */
export function modeledPath(graph: GraphModel, node: ViewerNode): HTMLElement {
  const injection = injectionEdges(graph, node.id)[0];
  const grant = fdaEdges(graph, node.id)[0];
  if (!injection || !grant)
    return para(
      "No complete injection-to-Full-Disk-Access path is recorded for this installation in the loaded snapshot.",
      "folio-note",
    );
  return pathFigure(graph, [injection.source, node.id, grant.target], undefined, [
    injection,
    grant,
  ]);
}
function pathPointDetail(node: ViewerNode): string {
  for (const key of ["bundle_id", "service"])
    if (typeof node.properties[key] === "string") return node.properties[key];
  return node.kind.replace(/^rs_/, "").replace(/([a-z])([A-Z])/g, "$1 $2");
}
/** Prefer a preferred key, then a traversable allowed relationship, then whatever is recorded. */
function jointEdge(
  graph: GraphModel,
  from: string,
  to: string,
  preferred: ReadonlySet<string>,
): GraphEdge | undefined {
  const candidates = (graph.outgoing.get(from) ?? [])
    .filter((entry) => entry.target === to)
    .map((entry) => entry.edge);
  return (
    candidates.find((edge) => preferred.has(`${edge.source}>${edge.kind}>${edge.target}`)) ??
    candidates.find(
      (edge) => edge.properties?._traversable !== false && edge.properties?.allowed !== false,
    ) ??
    candidates[0]
  );
}
function pathJoint(
  graph: GraphModel,
  from: string,
  to: string,
  preferred: ReadonlySet<string>,
): HTMLElement {
  const edge = jointEdge(graph, from, to, preferred);
  const basis = edge ? edgeBasis(edge) : "unknown";
  return el("div", { class: `folio-path-edge ${basis}` }, [
    el("code", { text: edge ? edgeKindLabel(edge.kind) : "Not recorded" }),
    el("span", { class: `folio-mark ${basis}`, text: basis }),
  ]);
}
function pathPoint(graph: GraphModel, id: string, first: boolean): HTMLElement {
  const node = graph.nodeById.get(id);
  if (!node)
    return el("div", { class: "folio-path-node" }, [
      el("strong", { text: id }),
      para("Not in snapshot"),
    ]);
  const modeled = first && node.properties.bundle_id === "attacker.payload";
  return el("div", { class: modeled ? "folio-path-node modeled" : "folio-path-node" }, [
    el("strong", { text: nodeName(node) }),
    para(modeled ? "Modeled starting point" : pathPointDetail(node)),
  ]);
}
/** Any ordered node list as specimens joined by the recorded relationship between neighbours. */
export function pathFigure(
  graph: GraphModel,
  nodeIds: string[],
  label = "Modeled exposure path",
  preferredEdges: readonly GraphEdge[] = [],
): HTMLElement {
  const preferred = new Set(preferredEdges.map((e) => `${e.source}>${e.kind}>${e.target}`));
  const children: HTMLElement[] = [];
  nodeIds.forEach((id, index) => {
    if (index > 0) children.push(pathJoint(graph, nodeIds[index - 1] ?? "", id, preferred));
    children.push(pathPoint(graph, id, index === 0));
  });
  return el("div", { class: "folio-path", role: "group", "aria-label": label }, children);
}
function recommendationTitle(node: ViewerNode): string {
  const titles: Record<string, string> = {
    harden_runtime: "Enable Hardened Runtime",
    library_validation: "Enable Library Validation",
    audit_fda_grants: "Review unnecessary Full Disk Access grants",
  };
  return value(
    node.properties.title ??
      titles[value(node.properties.key)] ??
      node.label ??
      node.properties.key,
  ).replaceAll("_", " ");
}
export function recommendationList(nodes: ViewerNode[]): HTMLElement {
  if (!nodes.length)
    return para(
      "No recommendations are recorded in the loaded evidence. This does not establish that no action is needed.",
      "folio-note",
    );
  return el(
    "ol",
    { class: "folio-recommendations" },
    nodes.map((node, index) => {
      const priority = value(node.properties.priority).toLowerCase();
      const tone = ["critical", "high", "medium", "low"].includes(priority) ? priority : "";
      const title = recommendationTitle(node);
      const text = value(node.properties.text ?? node.properties.description);
      const body = el("div", {}, [
        el("h3", { text: title }),
        el("span", { class: `folio-priority ${tone}`, text: priority }),
      ]);
      // Many recorded recommendations repeat their title as text; print it once.
      if (text.replace(/\.$/, "").toLowerCase() !== title.toLowerCase()) body.append(para(text));
      return el("li", {}, [el("span", { class: "folio-number", text: String(index + 1) }), body]);
    }),
  );
}

/** Restore a focused control when an asynchronous update replaces the document content. */
export function retainFolioFocus(root: HTMLElement): () => void {
  const active = document.activeElement;
  const controls = Array.from(
    root.querySelectorAll<HTMLElement>("button, input, select, [tabindex]"),
  );
  const index = controls.indexOf(active as HTMLElement);
  if (index < 0) return () => {};
  const identity = active?.getAttribute("id");
  const name = active?.getAttribute("name");
  const value = active?.getAttribute("value");
  return () => {
    const current = Array.from(
      root.querySelectorAll<HTMLElement>("button, input, select, [tabindex]"),
    );
    const match = identity
      ? current.find((item) => item.id === identity)
      : current.find(
          (item) =>
            item.getAttribute("name") === name &&
            item.getAttribute("value") === value &&
            name !== null,
        );
    (match ?? current[index])?.focus();
  };
}
