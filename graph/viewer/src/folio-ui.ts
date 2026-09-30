/** Small semantic building blocks for the evidence document. Untrusted data is always text. */
import { element } from "./runtime";
import { value, nodeName, injectionEdges, fdaEdges, coverageText } from "./folio-data";
import type { GraphModel, ViewerNode } from "./types";
export const el = element;
export const para = (text: string, className = ""): HTMLParagraphElement =>
  el("p", { text, class: className });
export const heading = (text: string): HTMLHeadingElement => el("h2", { text });
export function icon(name: string): SVGSVGElement {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 32 32");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("class", "folio-icon");
  const paths: Record<string, string> = {
    cube: "M16 2 29 9v15l-13 7L3 24V9z M3 9l13 8 13-8 M16 17v14 M9 6l13 8",
    drive: "M6 3h20l3 23H3z M3 26v4h26v-4 M8 27h2 M14 7c8 1 8 11 3 15",
    document: "M7 3h12l7 7v19H7z M19 3v8h7 M12 16h9 M12 21h9 M12 25h6",
    scope:
      "M16 2v6 M16 24v6 M2 16h6 M24 16h6 M28 16a12 12 0 1 1-24 0 12 12 0 0 1 24 0 M19 16a3 3 0 1 1-6 0 3 3 0 0 1 6 0",
    inspect:
      "M16 28H5V3h13l6 6v7 M18 3v7h6 M10 14h7 M10 19h4 M27 23a6 6 0 1 1-12 0 6 6 0 0 1 12 0 M25 27l5 4",
    report: "M5 28V18h3v10 M14 28V12h3v16 M24 28V4h3v24",
  };
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", paths[name] ?? paths.document ?? "");
  svg.append(path);
  return svg;
}
export function button(text: string, action: () => void, primary = false): HTMLButtonElement {
  const control = el("button", {
    type: "button",
    text,
    class: primary ? "folio-primary" : "folio-button",
  });
  if (primary) control.replaceChildren(icon("document"), el("span", { text }));
  control.addEventListener("click", action);
  return control;
}
export function facts(rows: [string, string][]): HTMLDListElement {
  return el(
    "dl",
    { class: "folio-facts" },
    rows.flatMap(([name, content]) => [el("dt", { text: name }), el("dd", { text: content })]),
  );
}
export function warning(graph: GraphModel): HTMLElement {
  return el("div", { class: "folio-warning", role: "note" }, [
    el("span", { text: "!", class: "folio-warning-icon", "aria-hidden": "true" }),
    para(coverageText(graph)),
  ]);
}
export function intro(title: string, text: string, note = "/* hello, friend. */"): HTMLElement {
  return el("header", { class: "folio-intro" }, [
    para(note, "folio-code"),
    el("h1", { text: title, tabindex: "-1" }),
    para(text, "folio-lead"),
  ]);
}
export function sequence(): HTMLElement {
  const aside = el("aside", { class: "folio-aside" }, [heading("Investigation sequence")]);
  const items = [
    [
      "Review scope",
      "Confirm the data source, collection coverage, and selected question for analysis.",
      "scope",
    ],
    [
      "Inspect evidence",
      "Explore modeled relationships in the local graph to validate the hypothesis.",
      "inspect",
    ],
    [
      "Export report",
      "Prepare evidence and recommendations from the loaded graph for review.",
      "report",
    ],
  ];
  aside.append(
    el(
      "ol",
      { class: "folio-sequence" },
      items.map(([title, description, symbol], index) =>
        el("li", {}, [
          el("span", { class: "folio-number", text: `0${index + 1}` }),
          el("span", { class: "folio-sequence-icon", "aria-hidden": "true" }, [
            icon(symbol ?? "document"),
          ]),
          el("div", {}, [el("h3", { text: title ?? "" }), para(description ?? "")]),
        ]),
      ),
    ),
  );
  return aside;
}
export function appIdentity(node: ViewerNode): HTMLElement {
  return el("div", { class: "folio-identity" }, [
    el("span", { class: "folio-document-icon", "aria-hidden": "true" }, [icon("document")]),
    el("div", {}, [
      heading(nodeName(node)),
      para(value(node.properties.bundle_id), "folio-code"),
      para(value(node.properties.path), "folio-code"),
    ]),
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
  const rows = [
    [
      "Full Disk Access grant",
      fdaEdges(graph, node.id).length ? "allowed" : "Unknown",
      fdaEdges(graph, node.id).length ? "observed" : "unknown",
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
              class: `folio-tag ${content === "disabled" || content === "false" ? "negative" : ""}`,
            }),
          ]),
          el("td", { text: basis ?? "" }),
        ]),
      ),
    ),
  ]);
}
export function modeledPath(graph: GraphModel, node: ViewerNode): HTMLElement {
  const injection = injectionEdges(graph, node.id)[0];
  const grant = fdaEdges(graph, node.id)[0];
  if (!injection || !grant)
    return para(
      "No complete injection-to-Full-Disk-Access path is recorded for this installation in the loaded snapshot.",
      "folio-note",
    );
  const source = graph.nodeById.get(injection.source);
  const point = (name: string, detail: string, symbol: string): HTMLElement =>
    el("div", { class: "folio-path-node" }, [
      icon(symbol),
      el("div", {}, [el("strong", { text: name }), para(detail)]),
    ]);
  return el("div", { class: "folio-path", role: "group", "aria-label": "Modeled exposure path" }, [
    point(source ? nodeName(source) : "attacker.payload", "synthetic starting point", "cube"),
    el("div", { class: "folio-path-edge inferred" }, [
      para("CAN_INJECT_INTO · inferred"),
      para("→"),
    ]),
    point(nodeName(node), value(node.properties.bundle_id), "document"),
    el("div", { class: "folio-path-edge" }, [para("HAS_TCC_GRANT · observed"), para("→")]),
    point("Full Disk Access", "TCC service", "drive"),
  ]);
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
    nodes.map((node, index) =>
      el("li", {}, [
        el("span", { class: "folio-number", text: String(index + 1).padStart(2, "0") }),
        el("div", {}, [
          el("span", {
            class: "folio-priority",
            text: value(node.properties.priority).toUpperCase(),
          }),
          el("h3", { text: recommendationTitle(node) }),
          para(value(node.properties.text ?? node.properties.description)),
        ]),
      ]),
    ),
  );
}

/** Restore a focused control when an asynchronous update replaces the document content. */
export function retainFolioFocus(root: HTMLElement): () => void {
  const active = document.activeElement;
  const controls = Array.from(root.querySelectorAll<HTMLElement>("button, input, [tabindex]"));
  const index = controls.indexOf(active as HTMLElement);
  if (index < 0) return () => {};
  const identity = active?.getAttribute("id");
  const name = active?.getAttribute("name");
  const value = active?.getAttribute("value");
  return () => {
    const current = Array.from(root.querySelectorAll<HTMLElement>("button, input, [tabindex]"));
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
