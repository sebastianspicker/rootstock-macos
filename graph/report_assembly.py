"""report_assembly.py — Report assembly, recommendations, and HTML conversion."""

from __future__ import annotations

import socket
from dataclasses import dataclass
from datetime import datetime, timezone

from tabulate import tabulate

from query_runner import discover_queries
from report_html import markdown_to_html as markdown_to_html
from report_recommendations import _append_recommendations_section
from report_sections import (
    _append_extended_query_sections,
    _append_threat_landscape,
    _append_vulnerability_mapping,
    _collect_active_categories,
)
from report_diagrams import mermaid_attack_paths_block, mermaid_tcc_pie
from report_formatters import (
    escape_report_value,
    format_generic_table,
    format_injectable_fda_table,
    format_electron_table,
    format_apple_event_table,
    format_tcc_overview_table,
    format_private_entitlement_table,
    format_executive_summary,
)


__all__ = ["assemble_report", "markdown_to_html"]


@dataclass
class ReportRows:
    injectable: list[dict]
    path: list[dict]
    electron: list[dict]
    private_entitlement: list[dict]
    apple_event: list[dict]
    tcc_overview: list[dict]
    tier_counts: dict[str, int]
    icloud: tuple[list[dict], list[dict], list[dict]]
    certificate: tuple[list[dict], list[dict], list[dict]]


# ── Themed Section Builders ──────────────────────────────────────────────────




# ── Report Assembly ───────────────────────────────────────────────────────────


def _get_query_rows(
    query_results: dict[str, list[dict] | str],
    filename: str,
) -> list[dict]:
    result = query_results.get(filename, [])
    return result if isinstance(result, list) else []



def _metadata_bool(value, true_label="Yes", false_label="No") -> str:
    if value is True:
        return true_label
    if value is False:
        return false_label
    return "unknown"


def _build_tier_counts(tier_rows: list[dict]) -> dict[str, int]:
    tier_counts: dict[str, int] = {}
    for row in tier_rows:
        raw_tier = row.get("tier")
        tier_label = f"Tier {raw_tier}" if raw_tier is not None else "Unclassified"
        tier_counts[tier_label] = tier_counts.get(tier_label, 0) + 1
    return tier_counts


def _build_top_attack_paths(
    injectable_rows: list[dict],
    electron_rows: list[dict],
) -> list[str]:
    top_paths: list[str] = []
    for row in injectable_rows[:2]:
        app = escape_report_value(row.get("app_name", "?"))
        methods = escape_report_value(row.get("injection_methods", []))
        top_paths.append(
            f"{app} has Full Disk Access and is injectable via `{methods}`."
        )
    for row in electron_rows[:1]:
        app = escape_report_value(row.get("app_name", "?"))
        perms = escape_report_value(row.get("inherited_permissions", []))
        top_paths.append(
            f"{app} (Electron) inherits TCC permissions ({perms}) via ELECTRON_RUN_AS_NODE abuse."
        )
    return top_paths


def _append_scan_metadata(sections: list[str], metadata: dict, now: str) -> None:
    meta_table = _scan_metadata_rows(metadata, now)

    sections.append("## Scan Metadata")
    sections.append(
        tabulate(
            [[escape_report_value(cell) for cell in row] for row in meta_table],
            tablefmt="github",
        )
    )
    sections.append("")


def _scan_metadata_rows(metadata: dict, now: str) -> list[list[str]]:
    return [
        *_base_scan_metadata_rows(metadata, now),
        *_count_scan_metadata_rows(metadata),
        *_icloud_metadata_rows(metadata),
    ]


def _base_scan_metadata_rows(metadata: dict, now: str) -> list[list[str]]:
    return [
        ["Hostname", metadata.get("hostname") or socket.gethostname()],
        ["macOS Version", metadata.get("macos_version") or "unknown"],
        ["Scan Timestamp", metadata.get("timestamp") or now],
        ["Scan ID", metadata.get("scan_id") or "unknown"],
        ["Collector Version", metadata.get("collector_version") or "unknown"],
        ["Elevation", _metadata_bool(metadata.get("is_root"), "root", "user")],
        ["Full Disk Access (collector)", _metadata_bool(metadata.get("has_fda"))],
    ]


def _count_scan_metadata_rows(metadata: dict) -> list[list[str]]:
    return [
        ["Total Apps Scanned", _metadata_count(metadata, "app_count", "unknown")],
        ["TCC Grants Found", _metadata_count(metadata, "tcc_grant_count", "unknown")],
        [
            "Entitlements Extracted",
            _metadata_count(metadata, "entitlement_count", "unknown"),
        ],
        ["Bluetooth Devices", _metadata_count(metadata, "bluetooth_device_count", "—")],
        ["File ACLs Audited", _metadata_count(metadata, "file_acl_count", "—")],
        ["Login Sessions", _metadata_count(metadata, "login_session_count", "—")],
    ]


def _metadata_count(metadata: dict, key: str, fallback: str) -> str:
    return str(metadata[key]) if key in metadata else fallback


def _icloud_metadata_rows(metadata: dict) -> list[list[str]]:
    icloud_signed = metadata.get("icloud_signed_in")
    if icloud_signed is False:
        return [
            ["iCloud Signed In", "No"],
            ["iCloud Drive", "No"],
            ["iCloud Keychain", "No"],
        ]
    return [
        ["iCloud Signed In", _metadata_bool(icloud_signed)],
        ["iCloud Drive", _metadata_bool(metadata.get("icloud_drive_enabled"))],
        ["iCloud Keychain", _metadata_bool(metadata.get("icloud_keychain_enabled"))],
    ]


def _append_executive_summary(
    sections: list[str],
    injectable_rows: list[dict],
    path_rows: list[dict],
    electron_rows: list[dict],
    apple_event_rows: list[dict],
    tier_counts: dict[str, int],
    icloud_exposure_count: int,
    certificate_risk_count: int,
) -> None:
    sections.append("## Executive Summary")
    sections.append(
        format_executive_summary(
            len(injectable_rows) + len(path_rows),
            len(electron_rows) + len(apple_event_rows),
            _build_top_attack_paths(injectable_rows, electron_rows),
            tier_counts=tier_counts or None,
            icloud_exposure_count=icloud_exposure_count,
            certificate_risk_count=certificate_risk_count,
        )
    )
    sections.append("")


def _append_vulnerability_intelligence(sections: list[str]) -> None:
    try:
        from cve_enrichment import enrich_registry

        enriched = enrich_registry()
    except Exception as exc:
        sections.append("### Vulnerability Intelligence")
        sections.append(
            "> **Warning:** CVE enrichment unavailable; vulnerability "
            f"intelligence summary omitted. Detail: {escape_report_value(exc)}"
        )
        sections.append("")
        return

    if not enriched:
        return

    summary = _vulnerability_intelligence_summary(enriched.values())
    if not _has_vulnerability_intelligence(summary):
        return

    sections.append("### Vulnerability Intelligence")
    sections.extend(_vulnerability_intelligence_lines(summary))
    sections.append("")


def _vulnerability_intelligence_summary(enriched_entries) -> dict:
    entries = list(enriched_entries)
    epss_entries = [entry for entry in entries if entry.epss_score is not None]
    return {
        "kev_count": sum(1 for entry in entries if entry.in_kev),
        "high_epss_count": sum(1 for entry in epss_entries if entry.epss_score > 0.3),
        "highest_epss": max(
            epss_entries,
            key=lambda entry: entry.epss_score,
            default=None,
        ),
    }


def _has_vulnerability_intelligence(summary: dict) -> bool:
    return bool(summary["kev_count"] or summary["high_epss_count"])


def _vulnerability_intelligence_lines(summary: dict) -> list[str]:
    lines: list[str] = []
    if summary["kev_count"]:
        lines.append(
            f"- **CISA KEV CVEs:** {summary['kev_count']} actively exploited vulnerabilities"
        )
    if summary["high_epss_count"]:
        lines.append(
            "- **High exploitation probability:** "
            f"{summary['high_epss_count']} CVE(s) with EPSS > 0.3"
        )
    highest_epss = summary["highest_epss"]
    if highest_epss and highest_epss.epss_score is not None:
        lines.append(
            f"- **Highest exploitation probability:** {highest_epss.base.cve_id} "
            f"(EPSS {highest_epss.epss_score:.2f})"
        )
    return lines


def _append_core_finding_sections(
    sections: list[str],
    injectable_rows: list[dict],
    path_rows: list[dict],
    electron_rows: list[dict],
    apple_event_rows: list[dict],
    tcc_overview_rows: list[dict],
    private_ent_rows: list[dict],
) -> None:
    _append_critical_finding_section(sections, injectable_rows, path_rows)
    _append_high_finding_sections(sections, electron_rows, apple_event_rows)
    _append_informational_finding_sections(
        sections,
        tcc_overview_rows,
        private_ent_rows,
    )


def _append_critical_finding_section(
    sections: list[str],
    injectable_rows: list[dict],
    path_rows: list[dict],
) -> None:
    sections.append("## Critical Findings: Injectable Apps with Privileged TCC Grants")
    sections.append(
        "> **Risk:** An attacker who controls a dylib can inject it into these apps "
        "and inherit their Full Disk Access grant — enabling read/write of TCC.db, "
        "Mail, SSH keys, and all user files without prompting the user."
    )
    sections.append("")
    sections.append(format_injectable_fda_table(injectable_rows))
    sections.append("")

    if path_rows:
        sections.append("### Attack Path Diagrams (Shortest Paths to Full Disk Access)")
        sections.append(mermaid_attack_paths_block(path_rows, max_paths=3))
    elif injectable_rows:
        sections.append("### Attack Path Diagrams")
        synthetic = [
            {
                "node_names": [
                    "attacker_payload",
                    r.get("app_name", "?"),
                    "Full Disk Access",
                ],
                "rel_types": ["CAN_INJECT_INTO", "HAS_TCC_GRANT"],
                "path_length": 2,
            }
            for r in injectable_rows[:3]
        ]
        sections.append(mermaid_attack_paths_block(synthetic, max_paths=3))
    sections.append("")


def _append_high_finding_sections(
    sections: list[str],
    electron_rows: list[dict],
    apple_event_rows: list[dict],
) -> None:
    sections.append("## High Findings: Electron TCC Inheritance")
    sections.append(
        "> **Risk:** Electron apps can be abused via the `ELECTRON_RUN_AS_NODE` environment "
        "variable to spawn a Node.js interpreter that inherits the parent process's TCC "
        "permissions. An attacker with local code execution can exploit this silently."
    )
    sections.append("")
    sections.append(format_electron_table(electron_rows))
    sections.append("")

    sections.append("## High Findings: Apple Event TCC Cascade")
    sections.append(
        "> **Risk:** An app with Apple Event automation permission over a privileged app "
        "can invoke that app's capabilities transitively, gaining effective access to the "
        "target's TCC grants without holding those grants directly."
    )
    sections.append("")
    sections.append(format_apple_event_table(apple_event_rows))
    sections.append("")


def _append_informational_finding_sections(
    sections: list[str],
    tcc_overview_rows: list[dict],
    private_ent_rows: list[dict],
) -> None:
    sections.append("## Informational: TCC Grant Overview")
    sections.append(format_tcc_overview_table(tcc_overview_rows))
    sections.append("")
    if tcc_overview_rows:
        sections.append("### TCC Permission Distribution")
        sections.append(mermaid_tcc_pie(tcc_overview_rows))
        sections.append("")

    sections.append("## Informational: Private Entitlement Audit")
    sections.append(
        "> Private Apple entitlements (`com.apple.private.*`) grant capabilities not "
        "available to App Store apps. Third-party apps holding these are high-value "
        "targets: compromising them may yield elevated privileges."
    )
    sections.append("")
    sections.append(format_private_entitlement_table(private_ent_rows))
    sections.append("")


def _append_raw_query_appendix(
    sections: list[str],
    query_results: dict[str, list[dict] | str],
    queries: list[dict],
) -> None:
    sections.append("## Appendix: Raw Query Results")
    sections.append(
        "Full output of each query for detailed analysis or import into other tools."
    )
    sections.append("")

    for q in queries:
        filename = q["filename"]
        result = query_results.get(filename)
        sections.append(f"### {filename}")
        if result is None:
            sections.append("_Not executed._")
        elif isinstance(result, str):
            sections.append(f"> **Error:** {result}")
        elif not result:
            sections.append("_No results._")
        else:
            sections.append(format_generic_table(result))
        sections.append("")


def _collect_report_rows(query_results: dict[str, list[dict] | str]) -> ReportRows:
    return ReportRows(
        injectable=_get_query_rows(query_results, "01-injectable-fda-apps.cypher"),
        path=_get_query_rows(query_results, "02-shortest-path-to-fda.cypher"),
        electron=_get_query_rows(query_results, "03-electron-tcc-inheritance.cypher"),
        private_entitlement=_get_query_rows(
            query_results, "04-private-entitlement-audit.cypher"
        ),
        apple_event=_get_query_rows(query_results, "05-appleevent-tcc-cascade.cypher"),
        tcc_overview=_get_query_rows(query_results, "07-tcc-grant-overview.cypher"),
        tier_counts=_build_tier_counts(
            _get_query_rows(query_results, "46-tier-classification.cypher")
        ),
        icloud=(
            _get_query_rows(query_results, "68-injectable-icloud-sync.cypher"),
            _get_query_rows(query_results, "69-cloudkit-container-injection.cypher"),
            _get_query_rows(query_results, "70-icloud-keychain-sync-exposure.cypher"),
        ),
        certificate=(
            _get_query_rows(query_results, "60-expired-cert-with-tcc.cypher"),
            _get_query_rows(query_results, "61-adhoc-signed-with-tcc.cypher"),
            _get_query_rows(query_results, "62-non-apple-ca-chain.cypher"),
        ),
    )


def _append_report_body(
    sections: list[str],
    query_results: dict[str, list[dict] | str],
    queries: list[dict],
    rows: ReportRows,
) -> None:
    _append_vulnerability_intelligence(sections)
    _append_core_finding_sections(
        sections,
        rows.injectable,
        rows.path,
        rows.electron,
        rows.apple_event,
        rows.tcc_overview,
        rows.private_entitlement,
    )
    _append_extended_query_sections(
        sections,
        query_results,
        queries,
        rows.tier_counts,
        rows.icloud[0],
    )
    _append_vulnerability_mapping(
        sections,
        _collect_active_categories(
            query_results,
            rows.injectable,
            rows.electron,
            rows.apple_event,
            rows.icloud,
            rows.certificate,
        ),
    )
    _append_threat_landscape(sections, query_results)
    _append_recommendations_section(
        sections,
        query_results,
        rows,
    )
    _append_raw_query_appendix(sections, query_results, queries)


def assemble_report(
    query_results: dict[str, list[dict] | str],
    metadata: dict,
) -> str:
    """Assemble the full Markdown report from query results and metadata."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    queries = discover_queries()
    rows = _collect_report_rows(query_results)
    sections: list[str] = []

    sections.append("# Rootstock Security Assessment Report")
    sections.append(f"_Generated: {now}_")
    sections.append("")
    _append_scan_metadata(sections, metadata, now)
    _append_executive_summary(
        sections,
        rows.injectable,
        rows.path,
        rows.electron,
        rows.apple_event,
        rows.tier_counts,
        sum(len(group) for group in rows.icloud),
        sum(len(group) for group in rows.certificate),
    )
    _append_report_body(sections, query_results, queries, rows)

    return "\n".join(sections)
