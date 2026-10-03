/** Standalone offline summary: semantic HTML, local styling, and escaped snapshot text only. */
import type { GraphModel } from "./types";
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

// A printed sheet: ink on paper, serif headings, small-caps field names, mono identifiers.
const stylesheet = `
:root{color-scheme:light dark;--paper:#f3efe6;--ink:#1d1b17;--muted:#4d483f;--rule:rgba(29,27,23,.16);--rule-strong:rgba(29,27,23,.34);--gap:#7c5d0a;--gap-rule:#b08a1e;--gap-dim:rgba(176,138,30,.12);--critical:#a3341d;--oxide:#b23f28;--serif:"Iowan Old Style",Charter,"Sitka Text",Cambria,Georgia,serif;--mono:"SF Mono",ui-monospace,Menlo,Consolas,monospace;font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:var(--paper);color:var(--ink)}
@media(prefers-color-scheme:dark){:root{--paper:#151411;--ink:#ebe5d8;--muted:#bbb3a3;--rule:rgba(235,229,216,.13);--rule-strong:rgba(235,229,216,.32);--gap:#d9b75e;--gap-rule:#8f7630;--gap-dim:rgba(217,183,94,.09);--critical:#e58a72;--oxide:#d9644b}}
*{box-sizing:border-box}body{margin:0}main{max-width:960px;margin:auto;padding:56px 32px 72px}
header{border-bottom:1px solid var(--rule-strong);padding-bottom:28px;margin-bottom:28px}.brand{color:var(--oxide);font:400 17px var(--serif)}
h1{font:400 clamp(30px,5vw,46px)/1.1 var(--serif);letter-spacing:-.01em;margin:18px 0}h2{font:400 23px/1.25 var(--serif);margin:40px 0 14px}
p{line-height:1.65;color:var(--muted)}dl{display:grid;grid-template-columns:150px minmax(0,1fr);margin:20px 0;padding:6px 20px;border:1px solid var(--rule-strong);outline:1px solid var(--rule);outline-offset:3px}dt,dd{margin:0;padding:10px 0;border-bottom:1px solid var(--rule)}dt{color:var(--muted);font:15px var(--serif);font-variant-caps:all-small-caps;letter-spacing:.05em}dd{font:13px/1.6 var(--mono)}dt:nth-last-child(2),dd:last-child{border-bottom:0}
.warning{padding:12px 16px;border-left:3px solid var(--gap-rule);background:var(--gap-dim)}p.warning{color:var(--ink)}.boundary{color:var(--muted)}
table{width:100%;border-collapse:collapse;text-align:left}caption{text-align:left;color:var(--muted);margin-bottom:12px}th,td{padding:12px 12px 12px 0;border-bottom:1px solid var(--rule);vertical-align:top}thead th{color:var(--muted);font:15px var(--serif);font-variant-caps:all-small-caps;letter-spacing:.06em;border-bottom-color:var(--rule-strong)}td{font-size:14px;line-height:1.5}td:nth-child(n+2){font-family:var(--mono);font-size:13px}
ol{padding-left:24px}li{padding:14px 0;border-bottom:1px solid var(--rule)}li p{margin:6px 0}.priority{color:var(--critical);font:15px var(--serif);font-variant-caps:all-small-caps;letter-spacing:.06em}.count{font:13px var(--mono);color:var(--muted)}
footer{border-top:1px solid var(--rule-strong);margin-top:44px;padding-top:18px;font:12px var(--mono);color:var(--muted)}p,dd,td,li{overflow-wrap:anywhere}.table-wrap{overflow-x:auto}
@media(max-width:600px){main{padding:28px 18px}dl{grid-template-columns:minmax(0,1fr);padding:4px 14px}dt{padding-bottom:0;border-bottom:0}th,td{font-size:12px;padding:10px 8px 10px 0}h2{font-size:21px}}
@media print{:root{--paper:#fff;--ink:#111;--muted:#333;--rule:#ccc;--rule-strong:#888;--gap:#5c4508;--gap-rule:#b08a1e;--gap-dim:#f7f3e3;--critical:#8f2c18;--oxide:#9c3622}main{padding:0}header,section,li,tr{break-inside:avoid}}
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
            class: "priority",
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
          el("p", { class: "brand", text: "Rootstock · Core" }),
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
