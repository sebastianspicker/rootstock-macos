"""Portable investigation outputs. All scan-derived text is escaped in HTML."""

from __future__ import annotations

import base64
import hashlib
import html
import json
import unicodedata

_SCRIPT = """const search=document.querySelector('#search');
const priority=document.querySelector('#priority');
function filter(){let count=0;const q=search.value.toLowerCase();
for(const row of document.querySelectorAll('.finding')){
row.hidden=!(row.textContent.toLowerCase().includes(q)&&(!priority.value||row.dataset.priority===priority.value));
if(!row.hidden)count++;}document.querySelector('#count').textContent=count+' findings shown';}
search.addEventListener('input',filter);priority.addEventListener('change',filter);filter();"""
_STYLE = """*{box-sizing:border-box}body{overflow-wrap:anywhere;margin:0;background:#f5f4ef;color:#202d31;font:16px/1.55 system-ui,sans-serif}
main{max-width:1120px;margin:auto;padding:40px 24px}h1{font-size:42px;letter-spacing:-1.5px;margin:12px 0}
h2{margin-top:42px}h3{margin:6px 0}p{max-width:85ch}a{color:#175763}header{border-bottom:2px solid #233e42;padding-bottom:22px}
.eyebrow{font:12px ui-monospace,monospace;letter-spacing:2px}.stats,.tools{display:flex;gap:16px;flex-wrap:wrap;align-items:center}
.stats strong{font-size:26px;display:block}.stats>div{padding:14px 24px 14px 0}.muted{color:#59696c}.warning{border-left:3px solid #a16e21;padding:8px 18px;background:#fbf5e7}
article{border:1px solid #cbd2cf;border-left:4px solid #b3873a;background:white;margin:16px 0;padding:20px}
article[data-priority=high]{border-left-color:#a34736}article[data-priority=low]{border-left-color:#648378}
.badge{font:12px ui-monospace,monospace;text-transform:uppercase;letter-spacing:.5px;color:#506265}
input,select{font:inherit;padding:10px;border:1px solid #a7b5af;border-radius:3px;background:white}input{width:min(100%,450px)}
summary{cursor:pointer;padding:10px 0;font-weight:600}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.5 ui-monospace,monospace;background:#eef2ef;padding:12px}
table{width:100%;border-collapse:collapse;font-size:14px}td,th{text-align:left;vertical-align:top;border-bottom:1px solid #cbd2cf;padding:9px;overflow-wrap:anywhere}th{font-weight:600}
.table-wrap{overflow:auto}section{scroll-margin-top:15px}nav{display:flex;gap:20px;flex-wrap:wrap;margin-top:20px}
[hidden]{display:none!important}@media print{.tools{display:none}main{padding:0}article{break-inside:avoid}details{display:block}}
"""


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _json(value: object) -> str:
    return _escape(json.dumps(value, indent=2, ensure_ascii=True))


def _table(headers: list[str], rows: list[list[object]]) -> str:
    return (
        '<div class="table-wrap"><table><thead><tr>'
        + "".join(f'<th scope="col">{_escape(header)}</th>' for header in headers)
        + "</tr></thead><tbody>"
        + "".join(
            "<tr>" + "".join(f"<td>{_escape(cell)}</td>" for cell in row) + "</tr>" for row in rows
        )
        + "</tbody></table></div>"
    )


def _node_label(node: dict) -> str:
    facts = node["facts"]
    return str(
        next(
            (
                facts[key]
                for key in (
                    "name",
                    "label",
                    "hostname",
                    "cve_id",
                    "subject",
                    "path",
                    "command",
                    "package_id",
                    "client",
                )
                if facts.get(key)
            ),
            node["kind"],
        )
    )


def _relationship_table(relationships: list[dict], nodes: dict[str, dict]) -> str:
    rows = []
    for row in relationships:
        source, target = nodes[row["source"]], nodes[row["target"]]
        rows.append(
            f'<tr><td><a href="#{_escape(source["id"])}">{_escape(_node_label(source))}</a></td>'
            f"<td>{_escape(row['relation'])}</td>"
            f'<td><a href="#{_escape(target["id"])}">{_escape(_node_label(target))}</a></td>'
            f"<td>{_escape(row['basis'])}</td></tr>"
        )
    return (
        '<div class="table-wrap"><table><thead><tr><th scope="col">Source</th>'
        '<th scope="col">Relationship</th><th scope="col">Target</th><th scope="col">Basis</th>'
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"
    )


def render_html(report: dict) -> str:
    scan, summary = report["scan"], report["summary"]
    script_hash = base64.b64encode(hashlib.sha256(_SCRIPT.encode()).digest()).decode()
    parts = [
        f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-{script_hash}'; base-uri 'none'; form-action 'none'">
<title>Rootstock investigation · {_escape(scan["hostname"])}</title><style>{_STYLE}</style></head><body><main>
<header><div class="eyebrow">ROOTSTOCK / LOCAL INVESTIGATION</div><h1>{_escape(scan["hostname"])}</h1>
<p class="muted">{_escape(scan["macos_version"])} · {_escape(scan["timestamp"])}<br>Scan {_escape(scan["scan_id"])}</p>
<div class="stats"><div><strong>{summary["findings"]}</strong>review findings</div><div><strong>{summary["evidence_records"]}</strong>evidence records</div>
<div><strong>{summary["relationships"]}</strong>associations</div></div>
<nav><a href="#findings">Review queue</a><a href="#coverage">Coverage</a><a href="#changes">Changes</a><a href="#evidence">Evidence graph</a></nav></header>
<p class="warning">This report reads one scan and local CVE caches. Priorities indicate what to review; they do not establish compromise. No network requests are made by this page.</p>
<section id="findings"><h2>Review queue</h2><div class="tools"><label>Search <input id="search" type="search" placeholder="CVE, path, rule or finding"></label>
<label for="priority">Priority</label><select id="priority"><option value="">All</option><option>high</option><option>medium</option><option>low</option></select>
<span id="count" role="status" aria-live="polite"></span></div>"""
    ]
    nodes = {node["id"]: node for node in report["evidence"]}
    for finding in report["findings"]:
        parts.append(
            f'<article class="finding" data-priority="{_escape(finding["priority"])}">'
            f'<div class="badge">{_escape(finding["priority"])} · {_escape(finding["confidence"])} · '
            f"{_escape(finding.get('baseline_status', 'current snapshot'))}</div>"
            f"<h3>{_escape(finding['title'])}</h3><p>{_escape(finding['explanation'])}</p>"
            f"<p><strong>Next step:</strong> {_escape(finding['next_step'])}</p>"
            f"<details><summary>Supporting evidence · {_escape(finding['rule_id'])}</summary>"
        )
        for evidence_id in finding["evidence_ids"]:
            node = nodes[evidence_id]
            parts.append(
                f'<a href="#{_escape(evidence_id)}">{_escape(node["kind"])} · {_escape(_node_label(node))}</a>'
                f"<pre>{_json(node['facts'])}</pre>"
            )
        if finding.get("baseline_evidence"):
            parts.append(f"<p>Baseline values</p><pre>{_json(finding['baseline_evidence'])}</pre>")
        parts.append("</details></article>")
    if not report["findings"]:
        parts.append(
            "<p>No review rules matched the available evidence. Check coverage before drawing conclusions.</p>"
        )
    parts.append('</section><section id="coverage"><h2>Collection and CVE coverage</h2>')
    parts.append(
        _table(
            ["Collection", "Records", "Status"],
            [[row["collection"], row["count"], row["status"]] for row in report["coverage"]],
        )
    )
    parts.append(
        "<p>Observed means records exist. Empty collections remain unknown because the legacy format does not prove complete collection.</p>"
    )
    parts.append(
        _table(
            ["Product", "Version", "CVE cache", "Freshness", "Complete", "Retained"],
            [
                [
                    row.get("name", row.get("bundle_id", "System components")),
                    row.get("version", "—"),
                    row["status"],
                    "stale" if row.get("stale") else "cached" if "stale" in row else "unknown",
                    row.get("complete", "unknown"),
                    row.get("retained_matches", "unknown"),
                ]
                for row in report["cve_coverage"]
            ],
        )
    )
    parts.append(
        f"<details><summary>Coverage details and collection errors</summary><pre>{_json({'cve_coverage': report['cve_coverage'], 'collection_errors': report['collection_errors']})}</pre></details></section>"
    )
    parts.append('<section id="changes"><h2>Changes since baseline</h2>')
    if report["baseline"]:
        baseline = report["baseline"]
        parts.append(
            f"<p>{len(baseline['added'])} newly observed · {len(baseline['changed'])} changed · "
            f"{len(baseline['no_longer_observed'])} no longer observed. Absence does not establish remediation.</p>"
            f"<details><summary>Inspect changed fields and records</summary><pre>{_json(baseline)}</pre></details>"
        )
    else:
        parts.append(
            "<p>No baseline supplied. Use --baseline with an earlier scan of this Mac to compare durable evidence.</p>"
        )
    parts.append(
        '</section><section id="evidence"><h2>Evidence graph</h2><p>Associations connect recorded paths and PIDs. Each record retains its normalized scan pointer or CVE cache source.</p>'
    )
    parts.append(_relationship_table(report["relationships"], nodes))
    for node in report["evidence"]:
        parts.append(
            f'<details id="{_escape(node["id"])}"><summary>{_escape(node["kind"])} · {_escape(_node_label(node))}</summary><pre>{_json(node)}</pre></details>'
        )
    parts.append(
        f"</section><details><summary>Provenance and limitations</summary><pre>{_json({'source_artifacts': report.get('source_artifacts', []), 'limitations': report['limitations'], 'ruleset_version': report['ruleset_version']})}</pre></details>"
    )
    parts.append(f"</main><script>{_SCRIPT}</script></body></html>\n")
    return "".join(parts)


def render_text(report: dict) -> str:
    scan = report["scan"]
    lines = [
        f"Rootstock investigation: {scan['hostname']}",
        f"Scan: {scan['scan_id']} · {scan['timestamp']}",
        f"{len(report['findings'])} review findings; {len(report['collection_errors'])} collection errors",
        "",
    ]
    for row in report["findings"]:
        lines.extend(
            [
                f"[{row['priority'].upper()} / {row['confidence']}] {row['title']}",
                row["explanation"],
                "Next: " + row["next_step"],
                "Evidence: " + ", ".join(row["evidence_ids"]),
                "",
            ]
        )
    lines.append("CVE coverage:")
    for row in report["cve_coverage"]:
        lines.append(
            f"  {row.get('name', row.get('bundle_id', 'System components'))}: {row['status']} "
            f"(stale={row.get('stale', 'unknown')}, complete={row.get('complete', 'unknown')})"
        )
    if report["baseline"]:
        baseline = report["baseline"]
        lines.append(
            f"Baseline: {len(baseline['added'])} new, {len(baseline['changed'])} changed, "
            f"{len(baseline['no_longer_observed'])} no longer observed"
        )
    lines.extend(["", *report["limitations"]])
    text = "\n".join(lines) + "\n"
    return "".join(
        char for char in text if char in "\n\t" or not unicodedata.category(char).startswith("C")
    )
