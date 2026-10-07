/** Standalone offline summary: semantic HTML, local styling, and escaped snapshot text only. */
import type { GraphModel, ViewerNode } from "./types";
import { element as el } from "./runtime";
import {
  scopeMetadata,
  coverageText,
  injectableApps,
  recommendations,
  affectedApps,
  nodeName,
  value,
} from "./folio-data";

// Plain scanner report: light by default with a dark variant, sans text, mono identifiers, flat tables.
const stylesheet = `
:root{color-scheme:light dark;--ink:#f4f6f9;--ink-deep:#fff;--pane:#fff;--pane-raised:#eef1f5;--text:#0f172a;--muted:#475569;--subtle:#5b6678;--rule:#dde3ea;--rule-strong:#768396;--gap:#8a5a00;--gap-rule:#b07d00;--gap-dim:rgba(217,154,0,.12);--critical:#b4123a;--high:#c2410c;--medium:#8f6a00;--low:#0e7490;--info:#5b6678;--on-severity:#fff;--font-ui:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,"Helvetica Neue",Arial,sans-serif;--font-mono:"SF Mono","JetBrains Mono",ui-monospace,Menlo,Consolas,"Liberation Mono",monospace;font:14px/1.5 var(--font-ui);background:var(--ink);color:var(--text)}
@media(prefers-color-scheme:dark){:root{--ink:#0d1117;--ink-deep:#090c10;--pane:#131820;--pane-raised:#1a212b;--text:#e6edf3;--muted:#a6b1bd;--subtle:#8a96a3;--rule:#262e39;--rule-strong:#6a7686;--gap:#e3b341;--gap-rule:#9e7a1e;--gap-dim:rgba(227,179,65,.1);--critical:#ff5c7c;--high:#ff8f4d;--medium:#e8c547;--low:#4fc3d9;--info:#8a96a3;--on-severity:#0d1117}}
*{box-sizing:border-box}body{margin:0}main{max-width:960px;margin:auto;padding:24px 24px 48px}
header{border-bottom:1px solid var(--rule);padding-bottom:16px;margin-bottom:16px}.brand{display:flex;align-items:center;gap:8px;margin:0;color:var(--text);font:600 14px var(--font-ui)}.mark{display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;border-radius:4px;background:var(--text);color:var(--ink);font:700 13px var(--font-mono)}
h1{font:600 22px/1.3 var(--font-ui);margin:12px 0 8px}h2{font:600 16px/1.3 var(--font-ui);margin:28px 0 8px}
p{margin:8px 0;color:var(--muted)}dl{display:grid;grid-template-columns:150px minmax(0,1fr);margin:12px 0;border:1px solid var(--rule);border-radius:4px;background:var(--pane)}dt,dd{margin:0;padding:8px 12px;border-bottom:1px solid var(--rule)}dt{background:var(--pane-raised);color:var(--subtle);font:600 11px/1.5 var(--font-ui);text-transform:uppercase;letter-spacing:.06em}dd{font:13px/1.5 var(--font-mono)}dt:nth-last-child(2),dd:last-child{border-bottom:0}
.warning{padding:8px 12px;border-left:3px solid var(--gap-rule);background:var(--gap-dim)}p.warning{color:var(--text)}.boundary{color:var(--muted)}
table{width:100%;border-collapse:collapse;text-align:left;background:var(--pane);border:1px solid var(--rule)}caption{text-align:left;color:var(--muted);margin-bottom:8px}th,td{padding:8px 12px;border-bottom:1px solid var(--rule);vertical-align:top}thead th{background:var(--pane-raised);color:var(--subtle);font:600 11px var(--font-ui);text-transform:uppercase;letter-spacing:.06em}tbody th{font-weight:600}td:nth-child(n+2){font-family:var(--font-mono);font-size:13px}
ol{padding-left:24px}li{padding:8px 0;border-bottom:1px solid var(--rule)}li p{margin:4px 0}.priority{display:inline-block;padding:1px 6px;border-radius:3px;background:var(--info);color:var(--on-severity);font:700 11px var(--font-ui);text-transform:uppercase;letter-spacing:.04em}.priority.critical{background:var(--critical)}.priority.high{background:var(--high)}.priority.medium{background:var(--medium)}.priority.low{background:var(--low)}.count{font:12px var(--font-mono);color:var(--muted)}
footer{border-top:1px solid var(--rule);margin-top:24px;padding-top:12px;font:12px var(--font-mono);color:var(--muted)}p,dd,td,li{overflow-wrap:anywhere}.table-wrap{overflow-x:auto}
@media(max-width:600px){main{padding:16px 12px}dl{grid-template-columns:minmax(0,1fr)}dt{border-bottom:0;padding-bottom:0}th,td{font-size:12px;padding:8px}}
@media print{:root{color-scheme:light;--ink:#fff;--ink-deep:#fff;--pane:#fff;--pane-raised:#eee;--text:#111;--muted:#333;--subtle:#444;--rule:#ccc;--rule-strong:#777;--gap:#6b4600;--gap-rule:#b07d00;--gap-dim:#f7f3e3;--critical:#b4123a;--high:#c2410c;--medium:#8f6a00;--low:#0e7490;--info:#5b6678;--on-severity:#fff}*{-webkit-print-color-adjust:exact;print-color-adjust:exact}main{padding:0}header,section,li,tr{break-inside:avoid}}
`;

function metadata(graph: GraphModel): HTMLElement {
  const scope = scopeMetadata(graph);
  const rows = [
    ["Source", scope.source],
    ["Host", scope.host],
    ["Collected", scope.collected],
    ["Scope", scope.scope],
  ];
  return el(
    "dl",
    {},
    rows.flatMap(([label, text]) => [
      el("dt", { text: label ?? "" }),
      el("dd", { text: text ?? "Unknown" }),
    ]),
  );
}
function applications(graph: GraphModel): HTMLElement {
  const apps = injectableApps(graph);
  const section = el("section", {}, [
    el("h2", { text: "Applications with modeled injection and Full Disk Access" }),
  ]);
  if (!apps.length) {
    section.append(
      el("p", {
        text: "No matching applications are recorded in this snapshot. Missing evidence does not establish that the host is safe.",
      }),
    );
    return section;
  }
  const columns = ["Application", "Bundle ID", "Installation path"];
  const table = el("table", {}, [
    el("caption", {
      text: "An allowed Full Disk Access grant and modeled injection relationship are both present in the loaded snapshot.",
    }),
    el("thead", {}, [
      el(
        "tr",
        {},
        columns.map((text) => el("th", { scope: "col", text })),
      ),
    ]),
    el(
      "tbody",
      {},
      apps.map((node) =>
        el("tr", {}, [
          el("th", { scope: "row", text: nodeName(node) }),
          el("td", { text: value(node.properties.bundle_id) }),
          el("td", { text: value(node.properties.path) }),
        ]),
      ),
    ),
  ]);
  section.append(el("div", { class: "table-wrap" }, [table]));
  return section;
}
function priorityClass(node: ViewerNode): string {
  const priority = value(node.properties.priority).toLowerCase();
  return ["critical", "high", "medium", "low"].includes(priority)
    ? `priority ${priority}`
    : "priority";
}
function advice(graph: GraphModel): HTMLElement {
  const nodes = recommendations(graph);
  const section = el("section", {}, [el("h2", { text: "Loaded recommendations" })]);
  if (!nodes.length) {
    section.append(
      el("p", {
        text: "No recommendations are recorded in the loaded snapshot. This does not establish that no action is needed.",
      }),
    );
    return section;
  }
  section.append(
    el(
      "ol",
      {},
      nodes.map((node) =>
        el("li", {}, [
          el("span", {
            class: priorityClass(node),
            text: `${value(node.properties.priority).toUpperCase()} PRIORITY`,
          }),
          el("p", { text: value(node.properties.text ?? node.label) }),
          el("span", {
            class: "count",
            text: `${affectedApps(graph, node.id)} affected application(s) in this snapshot`,
          }),
        ]),
      ),
    ),
  );
  return section;
}
export function snapshotHtml(graph: GraphModel): string {
  const page = el("html", { lang: "en" }, [
    el("head", {}, [
      el("meta", { charset: "utf-8" }),
      el("meta", { name: "viewport", content: "width=device-width, initial-scale=1" }),
      el("title", { text: "Rootstock local snapshot summary" }),
      el("style", { text: stylesheet }),
    ]),
    el("body", {}, [
      el("main", {}, [
        el("header", {}, [
          el("p", { class: "brand" }, [
            el("span", { class: "mark", text: "R", "aria-hidden": "true" }),
            el("span", { text: "Rootstock · Core" }),
          ]),
          el("h1", { text: "Local snapshot summary" }),
          el("p", {
            class: "boundary",
            text: "This document summarizes the loaded viewer snapshot. It is not a full Neo4j assessment report. Modeled exposure is not confirmation of compromise.",
          }),
        ]),
        metadata(graph),
        el("p", { class: "warning", text: coverageText(graph) }),
        applications(graph),
        advice(graph),
        el("footer", {
          text: "Prepared from local snapshot evidence. Host settings are unchanged. Recommendations still require review and action.",
        }),
      ]),
    ]),
  ]);
  return `<!doctype html>\n${page.outerHTML}`;
}
