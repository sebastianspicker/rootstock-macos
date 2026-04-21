"""report_formatters.py — Table and section formatters for Rootstock reports."""

from __future__ import annotations

import logging

from tabulate import tabulate

from utils import list_or_str

logger = logging.getLogger(__name__)


def format_no_findings() -> str:
    return "_No findings in this category._"


ColumnSpec = list[tuple[str, str, str | None]]
"""List of (header_label, dict_key, default_value) tuples for _format_table."""


def _format_table(rows: list[dict], columns: ColumnSpec) -> str:
    """Generic table builder: maps row dicts to a Markdown table via a column spec.

    Each entry in *columns* is ``(header, key, default)`` — the dict key to extract
    and the fallback value.  Uses :func:`list_or_str` for list→string coercion.
    Returns a GitHub-flavoured Markdown table via :func:`tabulate`.
    """
    if not rows:
        return format_no_findings()
    table_rows = [
        [list_or_str(row.get(key, default)) for _, key, default in columns]
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
    table_rows = [[list_or_str(row.get(h)) for h in all_keys] for row in rows]
    return tabulate(table_rows, headers=all_keys, tablefmt="github")


def format_injectable_fda_table(rows: list[dict]) -> str:
    """Format Query 01 results: injectable apps with Full Disk Access."""
    if not rows:
        return format_no_findings()

    table_rows = []
    for r in rows:
        methods = list_or_str(r.get("injection_methods", []))
        table_rows.append([
            r.get("app_name", "?"),
            r.get("team_id") or "—",
            methods,
            r.get("bundle_id", "?"),
        ])

    headers = ["App Name", "Team ID", "Injection Method(s)", "Bundle ID"]
    table = tabulate(table_rows, headers=headers, tablefmt="github")

    risk_lines = []
    for r in rows:
        app = r.get("app_name", "?")
        methods = list_or_str(r.get("injection_methods", []))
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
    if not rows:
        return format_no_findings()

    table_rows = []
    for r in rows:
        ents = list_or_str(r.get("private_entitlements", []))
        injectable = "Yes" if r.get("is_injectable") else "No"
        table_rows.append([
            r.get("app_name", "?"),
            ents,
            injectable,
        ])

    headers = ["App", "Private Entitlements", "Injectable?"]
    return tabulate(table_rows, headers=headers, tablefmt="github")


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
    total_findings = critical_count + high_count
    if total_findings == 0:
        overall = "LOW"
    elif critical_count > 0:
        overall = "CRITICAL"
    elif high_count > 3:
        overall = "HIGH"
    else:
        overall = "MEDIUM"

    lines = [
        f"**Overall Risk: {overall}**",
        "",
        "| Severity | Count | Indicator |",
        "|----------|------:|-----------|",
        f"| Critical | {critical_count} |{_risk_bar(critical_count)} |",
        f"| High     | {high_count} |{_risk_bar(high_count)} |",
    ]

    if tier_counts:
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

    if icloud_exposure_count:
        lines.append(f"\n**iCloud Exposure:** {icloud_exposure_count} injectable app(s) with iCloud entitlements")

    if certificate_risk_count:
        lines.append(f"\n**Certificate Risk:** {certificate_risk_count} app(s) with expired/ad-hoc/non-Apple CA certs")

    lines.append("")
    lines.append("**Top Attack Paths:**")

    if top_paths:
        for i, path in enumerate(top_paths[:3], 1):
            lines.append(f"{i}. {path}")
    else:
        lines.append("_No attack paths discovered._")

    return "\n".join(lines)


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

    # Try to load enrichment data (graceful if unavailable)
    enriched_map: dict = {}
    try:
        from cve_enrichment import enrich_registry
        enriched_map = enrich_registry()
    except Exception as exc:
        logger.info("CVE enrichment unavailable, continuing without it: %s", exc)

    # ── CVE table (deduplicated, sorted by EPSS desc then CVSS desc) ─────
    seen_cves: set[str] = set()
    cve_priority: dict[str, str] = {}
    for ctx in contexts:
        assert isinstance(ctx, AttackContext)
        for cve in ctx.cves:
            if cve.cve_id not in cve_priority:
                cve_priority[cve.cve_id] = ctx.remediation_priority

    all_cves = []
    for ctx in contexts:
        for cve in ctx.cves:
            if cve.cve_id not in seen_cves:
                seen_cves.add(cve.cve_id)
                all_cves.append(cve)

    # Sort by EPSS descending (when available), then CVSS descending
    def _sort_key(cve):
        enriched = enriched_map.get(cve.cve_id)
        epss = getattr(enriched, "epss_score", None) if enriched else None
        return (epss if epss is not None else -1, cve.cvss_score)

    all_cves.sort(key=_sort_key, reverse=True)

    cve_rows: list[list[str]] = []

    for cve in all_cves:
        enriched = enriched_map.get(cve.cve_id)
        epss_str = f"{enriched.epss_score:.2f}" if enriched and enriched.epss_score is not None else "—"
        kev_str = "KEV" if enriched and enriched.in_kev else ""

        cve_rows.append([
            cve.cve_id,
            str(cve.cvss_score),
            epss_str,
            kev_str,
            _exploitation_icon(getattr(cve, "exploitation_status", "theoretical")),
            cve.title,
            cve.patched_version or "—",
            cve_priority.get(cve.cve_id, "—"),
        ])

    parts: list[str] = []

    if cve_rows:
        cve_headers = ["CVE ID", "CVSS", "EPSS", "KEV", "Exploited", "Title", "Patched", "Priority"]
        parts.append("### CVE Reference")
        parts.append(tabulate(cve_rows, headers=cve_headers, tablefmt="github"))
        parts.append("")

    # ── ATT&CK techniques table (deduplicated) ──────────────────────────
    seen_techniques: set[str] = set()
    technique_rows: list[list[str]] = []
    technique_categories: dict[str, list[str]] = {}

    for ctx in contexts:
        for tech in ctx.techniques:
            if tech.technique_id not in technique_categories:
                technique_categories[tech.technique_id] = []
            technique_categories[tech.technique_id].append(ctx.category)

    for ctx in contexts:
        for tech in ctx.techniques:
            if tech.technique_id not in seen_techniques:
                seen_techniques.add(tech.technique_id)
                categories = technique_categories.get(tech.technique_id, [])
                technique_rows.append([
                    tech.technique_id,
                    tech.name,
                    tech.tactic,
                    ", ".join(sorted(set(categories))),
                ])

    if technique_rows:
        tech_headers = ["ID", "Technique", "Tactic", "Relevant Findings"]
        parts.append("### MITRE ATT&CK Techniques")
        parts.append(tabulate(technique_rows, headers=tech_headers, tablefmt="github"))
        parts.append("")

    return "\n".join(parts) if parts else "_No CVE or ATT&CK references applicable._"
