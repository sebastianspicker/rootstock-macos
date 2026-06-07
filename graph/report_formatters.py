"""report_formatters.py — Table and section formatters for Rootstock reports."""

from __future__ import annotations

import logging
import html as html_mod

from tabulate import tabulate

from utils import list_or_str

logger = logging.getLogger(__name__)


def format_no_findings() -> str:
    return "_No findings in this category._"


ColumnSpec = list[tuple[str, str, str | None]]
"""List of (header_label, dict_key, default_value) tuples for _format_table."""


def escape_report_value(value: object) -> str:
    """Escape untrusted graph values before they enter Markdown/HTML reports."""
    return html_mod.escape(list_or_str(value), quote=True)


def _format_table(rows: list[dict], columns: ColumnSpec) -> str:
    """Generic table builder: maps row dicts to a Markdown table via a column spec.

    Each entry in *columns* is ``(header, key, default)`` — the dict key to extract
    and the fallback value.  Uses :func:`list_or_str` for list→string coercion.
    Returns a GitHub-flavoured Markdown table via :func:`tabulate`.
    """
    if not rows:
        return format_no_findings()
    table_rows = [
        [escape_report_value(row.get(key, default)) for _, key, default in columns]
        for row in rows
    ]
    headers = [h for h, _, _ in columns]
    return tabulate(table_rows, headers=headers, tablefmt="github")


def format_generic_table(rows: list[dict]) -> str:
    """Format any query result set as a GitHub-flavoured Markdown table."""
    if not rows:
        return format_no_findings()

    all_keys: list[str] = []
    seen_keys: set[str] = set()
    for row in rows:
        for k in row.keys():
            if k not in seen_keys:
                all_keys.append(k)
                seen_keys.add(k)
    table_rows = [[escape_report_value(row.get(h)) for h in all_keys] for row in rows]
    return tabulate(table_rows, headers=all_keys, tablefmt="github")


def format_injectable_fda_table(rows: list[dict]) -> str:
    """Format Query 01 results: injectable apps with Full Disk Access."""
    if not rows:
        return format_no_findings()

    table_rows = []
    for r in rows:
        methods = escape_report_value(r.get("injection_methods", []))
        table_rows.append([
            escape_report_value(r.get("app_name", "?")),
            escape_report_value(r.get("team_id") or "—"),
            methods,
            escape_report_value(r.get("bundle_id", "?")),
        ])

    headers = ["App Name", "Team ID", "Injection Method(s)", "Bundle ID"]
    table = tabulate(table_rows, headers=headers, tablefmt="github")

    risk_lines = []
    for r in rows:
        app = escape_report_value(r.get("app_name", "?"))
        methods = escape_report_value(r.get("injection_methods", []))
        risk_lines.append(
            f"- **{app}**: Attacker can inject via `{methods}` to inherit Full Disk Access."
        )

    return table + "\n\n" + "\n".join(risk_lines)


def format_electron_table(rows: list[dict]) -> str:
    """Format Query 03 results: Electron apps with TCC inheritance."""
    return _format_table(rows, [
        ("Electron App", "app_name", "?"),
        ("Bundle ID", "bundle_id", "?"),
        ("Inherited Permissions", "inherited_permissions", "—"),
        ("Count", "permission_count", "0"),
    ])


def format_apple_event_table(rows: list[dict]) -> str:
    """Format Query 05 results: Apple Event TCC cascade."""
    return _format_table(rows, [
        ("Source App", "source_app", "?"),
        ("Target App", "target_app", "?"),
        ("Gained Permission", "permission_gained", "?"),
    ])


def format_tcc_overview_table(rows: list[dict]) -> str:
    """Format Query 07 section-1 results: TCC grant distribution."""
    return _format_table(rows, [
        ("Permission", "permission", "?"),
        ("TCC Service", "service", "?"),
        ("Allowed", "allowed_count", "0"),
        ("Denied", "denied_count", "0"),
        ("Total", "total_grants", "0"),
    ])


def format_private_entitlement_table(rows: list[dict]) -> str:
    """Format Query 04 results: private entitlement audit."""
    formatted_rows = [
        {**row, "is_injectable": "Yes" if row.get("is_injectable") else "No"}
        for row in rows
    ]
    return _format_table(formatted_rows, [
        ("App", "app_name", "?"),
        ("Private Entitlements", "private_entitlements", "—"),
        ("Injectable?", "is_injectable", "No"),
    ])


def _risk_bar(count: int, max_count: int = 20) -> str:
    """Return a text-based risk indicator bar for Markdown reports."""
    if count == 0:
        return ""
    filled = min(count, max_count)
    return " `" + "#" * filled + ("+" if count > max_count else "") + "`"


def format_executive_summary(
    critical_count: int,
    high_count: int,
    top_paths: list[str],
    tier_counts: dict[str, int] | None = None,
    icloud_exposure_count: int = 0,
    certificate_risk_count: int = 0,
) -> str:
    """Format the Executive Summary section with severity indicators."""
    lines = [
        f"**Overall Risk: {_overall_risk(critical_count, high_count)}**",
        "",
        "| Severity | Count | Indicator |",
        "|----------|------:|-----------|",
        f"| Critical | {critical_count} |{_risk_bar(critical_count)} |",
        f"| High     | {high_count} |{_risk_bar(high_count)} |",
    ]

    _append_tier_classification(lines, tier_counts)
    _append_exposure_summary(lines, icloud_exposure_count, certificate_risk_count)
    _append_top_attack_paths(lines, top_paths)
    return "\n".join(lines)


def _overall_risk(critical_count: int, high_count: int) -> str:
    total_findings = critical_count + high_count
    if total_findings == 0:
        return "LOW"
    if critical_count > 0:
        return "CRITICAL"
    if high_count > 3:
        return "HIGH"
    return "MEDIUM"


def _append_tier_classification(
    lines: list[str],
    tier_counts: dict[str, int] | None,
) -> None:
    if not tier_counts:
        return
    t0 = tier_counts.get('Tier 0', 0)
    t1 = tier_counts.get('Tier 1', 0)
    t2 = tier_counts.get('Tier 2', 0)
    lines.append("")
    lines.append(
        f"**Tier Classification:** "
        f"**{t0}** Tier 0 (crown jewels) | "
        f"**{t1}** Tier 1 (high value) | "
        f"**{t2}** Tier 2 (standard)"
    )


def _append_exposure_summary(
    lines: list[str],
    icloud_exposure_count: int,
    certificate_risk_count: int,
) -> None:
    if icloud_exposure_count:
        lines.append(
            f"\n**iCloud Exposure:** {icloud_exposure_count} "
            "injectable app(s) with iCloud entitlements"
        )
    if certificate_risk_count:
        lines.append(
            f"\n**Certificate Risk:** {certificate_risk_count} "
            "app(s) with expired/ad-hoc/non-Apple CA certs"
        )


def _append_top_attack_paths(lines: list[str], top_paths: list[str]) -> None:
    lines.append("")
    lines.append("**Top Attack Paths:**")

    if top_paths:
        for i, path in enumerate(top_paths[:3], 1):
            lines.append(f"{i}. {path}")
    else:
        lines.append("_No attack paths discovered._")


# ── Vulnerability & ATT&CK Summary ──────────────────────────────────────────


def _exploitation_icon(status: str) -> str:
    """Return a visual indicator for exploitation status in the CVE table."""
    if status == "actively_exploited":
        return "[!!!] Active"
    if status == "poc_available":
        return "[!!] PoC"
    if status == "theoretical":
        return "[!] Theory"
    return ""


def _load_cve_enrichment() -> tuple[dict, bool]:
    """Load optional CVE enrichment data and report whether it is unavailable."""
    try:
        from cve_enrichment import enrich_registry
        enriched_map = enrich_registry() or {}
    except Exception as exc:
        logger.warning("CVE enrichment unavailable, continuing without it: %s", exc)
        return {}, True

    if enriched_map:
        return enriched_map, False

    logger.warning(
        "CVE enrichment data unavailable; EPSS/KEV report columns omitted. "
        "Run with --refresh-cve to populate."
    )
    return {}, True


def _context_cve_priorities(contexts: list) -> dict[str, str]:
    cve_priority: dict[str, str] = {}
    for ctx in contexts:
        for cve in ctx.cves:
            cve_priority.setdefault(cve.cve_id, ctx.remediation_priority)
    return cve_priority


def _unique_context_cves(contexts: list) -> list:
    seen_cves: set[str] = set()
    all_cves = []
    for ctx in contexts:
        for cve in ctx.cves:
            if cve.cve_id in seen_cves:
                continue
            seen_cves.add(cve.cve_id)
            all_cves.append(cve)
    return all_cves


def _cve_sort_key(cve, enriched_map: dict) -> tuple[float, float]:
    enriched = enriched_map.get(cve.cve_id)
    epss = getattr(enriched, "epss_score", None) if enriched else None
    return (epss if epss is not None else -1, cve.cvss_score)


def _cve_summary_rows(
    cves: list,
    cve_priority: dict[str, str],
    enriched_map: dict,
    enrichment_unavailable: bool,
) -> list[list[str]]:
    rows: list[list[str]] = []
    for cve in cves:
        enriched = enriched_map.get(cve.cve_id)
        row = [
            cve.cve_id,
            str(cve.cvss_score),
            _exploitation_icon(getattr(cve, "exploitation_status", "theoretical")),
            cve.title,
            cve.patched_version or "—",
            cve_priority.get(cve.cve_id, "—"),
        ]
        if not enrichment_unavailable:
            epss_str = (
                f"{enriched.epss_score:.2f}"
                if enriched and enriched.epss_score is not None
                else "—"
            )
            kev_str = "KEV" if enriched and enriched.in_kev else ""
            row[2:2] = [epss_str, kev_str]
        rows.append(row)
    return rows


def _cve_summary_headers(enrichment_unavailable: bool) -> list[str]:
    headers = ["CVE ID", "CVSS", "Exploited", "Title", "Patched", "Priority"]
    if not enrichment_unavailable:
        headers[2:2] = ["EPSS", "KEV"]
    return headers


def _append_cve_summary(
    parts: list[str],
    cve_rows: list[list[str]],
    enrichment_unavailable: bool,
) -> None:
    if not cve_rows:
        return
    parts.append("### CVE Reference")
    if enrichment_unavailable:
        parts.append(
            "> CVE enrichment data unavailable -- EPSS/KEV columns omitted. "
            "Run with --refresh-cve to populate."
        )
    parts.append(
        tabulate(
            cve_rows,
            headers=_cve_summary_headers(enrichment_unavailable),
            tablefmt="github",
        )
    )
    parts.append("")


def _technique_categories(contexts: list) -> dict[str, list[str]]:
    categories: dict[str, list[str]] = {}
    for ctx in contexts:
        for tech in ctx.techniques:
            categories.setdefault(tech.technique_id, []).append(ctx.category)
    return categories


def _technique_summary_rows(contexts: list) -> list[list[str]]:
    seen_techniques: set[str] = set()
    categories = _technique_categories(contexts)
    rows: list[list[str]] = []
    for ctx in contexts:
        for tech in ctx.techniques:
            if tech.technique_id in seen_techniques:
                continue
            seen_techniques.add(tech.technique_id)
            rows.append([
                tech.technique_id,
                tech.name,
                tech.tactic,
                ", ".join(sorted(set(categories.get(tech.technique_id, [])))),
            ])
    return rows


def _append_technique_summary(parts: list[str], technique_rows: list[list[str]]) -> None:
    if not technique_rows:
        return
    tech_headers = ["ID", "Technique", "Tactic", "Relevant Findings"]
    parts.append("### MITRE ATT&CK Techniques")
    parts.append(tabulate(technique_rows, headers=tech_headers, tablefmt="github"))
    parts.append("")


def format_vulnerability_summary(contexts: list) -> str:
    """
    Render CVE reference and ATT&CK technique tables from a list of AttackContext objects.

    Only includes CVEs and techniques that are relevant to the scanned host's active
    finding categories. Deduplicates across categories.

    When live enrichment data (EPSS + CISA KEV) is available, includes EPSS score
    and KEV status columns and sorts by EPSS descending (more actionable than CVSS).
    """
    from cve_reference import AttackContext  # deferred to avoid circular import

    if not contexts:
        return "_No CVE or ATT&CK references applicable to findings on this host._"

    for ctx in contexts:
        if not isinstance(ctx, AttackContext):
            raise TypeError("contexts must contain AttackContext instances")

    enriched_map, enrichment_unavailable = _load_cve_enrichment()
    cve_priority = _context_cve_priorities(contexts)
    all_cves = _unique_context_cves(contexts)

    all_cves.sort(key=lambda cve: _cve_sort_key(cve, enriched_map), reverse=True)
    cve_rows = _cve_summary_rows(
        all_cves,
        cve_priority,
        enriched_map,
        enrichment_unavailable,
    )

    parts: list[str] = []
    _append_cve_summary(parts, cve_rows, enrichment_unavailable)
    _append_technique_summary(parts, _technique_summary_rows(contexts))

    return "\n".join(parts) if parts else "_No CVE or ATT&CK references applicable._"
