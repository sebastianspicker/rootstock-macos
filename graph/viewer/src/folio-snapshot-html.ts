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

const stylesheet = `
:root{color-scheme:dark;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0c1213;color:#f2f1ee}
*{box-sizing:border-box}body{margin:0}main{max-width:1100px;margin:auto;padding:48px 32px 64px}
header{border-bottom:1px solid #43514e;padding-bottom:28px;margin-bottom:28px}.brand{color:#ff897c;font:14px ui-monospace,monospace;letter-spacing:1px}
h1{font-size:clamp(30px,5vw,48px);line-height:1.15;letter-spacing:-1px;margin:20px 0}h2{font-size:24px;margin:36px 0 18px}
p{line-height:1.65;color:#bdc9d0}dl{display:grid;grid-template-columns:150px minmax(0,1fr);margin:20px 0}dt,dd{margin:0;padding:12px 0;border-bottom:1px solid #303d3e}dd{font:14px/1.6 ui-monospace,monospace;color:#bdc9d0}
.warning{padding:18px;border:1px solid #756d3f;background:#202217;border-radius:4px;color:#e8ddb0}.boundary{color:#bdc9d0}
table{width:100%;border-collapse:collapse;text-align:left}caption{text-align:left;color:#bdc9d0;margin-bottom:12px}th,td{padding:14px 12px 14px 0;border-bottom:1px solid #303d3e;vertical-align:top}thead th{color:#b3d7ad;font-size:13px;font-weight:500}td{font-size:14px;line-height:1.5}td:nth-child(n+2){font-family:ui-monospace,monospace}
ol{padding-left:24px}li{padding:16px 0;border-bottom:1px solid #303d3e}li p{margin:8px 0}.priority{color:#ff978d;font:12px ui-monospace,monospace}.count{font:13px ui-monospace,monospace;color:#b3d7ad}
footer{border-top:1px solid #43514e;margin-top:40px;padding-top:20px;font:12px ui-monospace,monospace;color:#bdc9d0}p,dd,td,li{overflow-wrap:anywhere}.table-wrap{overflow-x:auto}
@media(max-width:600px){main{padding:28px 18px}dl{grid-template-columns:90px minmax(0,1fr)}th,td{font-size:12px;padding:10px 8px 10px 0}h2{font-size:21px}}
@media print{:root{color-scheme:light;background:white;color:#111}p,dd,footer,.boundary{color:#333}.warning{background:#faf8e9;color:#333}.brand,.priority,.count,thead th{color:#333}main{padding:0}header,section,li,tr{break-inside:avoid}}
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
          el("p", { class: "brand", text: "ROOTSTOCK / CORE" }),
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
