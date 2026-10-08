"""report_formatters_host.py - Summary lines and tables for host evidence in the report.

Every count is derived from query rows (104-109) or from the collector scan JSON;
nothing is assumed. A source the collector recorded errors for is reported as
"not collected" rather than as zero.
"""

from __future__ import annotations

import re

from tabulate import tabulate

from .report_formatters import ColumnSpec, escape_report_value, escape_table_cell
from .report_query_results import query_rows

__all__ = [
    "INSTALLED_CVE_COLUMNS",
    "MACOS_CVE_COLUMNS",
    "format_cve_match_table",
    "host_evidence_summary_lines",
    "host_inventory_metadata_rows",
]

INSTALLED_CVE_COLUMNS: ColumnSpec = [
    ("Application", "app_name", None),
    ("Bundle ID", "bundle_id", None),
    ("Version", "app_version", None),
    ("CVEs", "cve_count", 0),
    ("KEV", "kev_count", 0),
    ("Max CVSS", "max_cvss", None),
    ("Top CVEs", "top_cves", None),
]

MACOS_CVE_COLUMNS: ColumnSpec = [
    ("Host", "hostname", None),
    ("macOS", "macos_version", None),
    ("CVEs", "cve_count", 0),
    ("KEV", "kev_count", 0),
    ("Max CVSS", "max_cvss", None),
    ("Top CVEs", "top_cves", None),
]

_Q104 = "104-installed-software-cves.cypher"
_Q105 = "105-macos-version-cves.cypher"
_Q106 = "106-network-listeners-by-exposure.cypher"

# Collector error sources (CollectionError.source) behind each summary line; lines
# keyed by _NO_SOURCE come from data the collector always records or from NVD.
_NO_SOURCE = ""
_ERROR_SOURCES = {
    "listeners": "Network Listeners",
    "trust": "Trust Settings",
    "extensions": "Browser Extensions",
}

# Scan JSON counts shown in the metadata table when the scan file is given.
_INVENTORY_METADATA_ROWS = (
    ("Running Processes", "process_count"),
    ("Network Listeners", "network_listener_count"),
    ("Trusted Certificates (user/admin)", "trusted_certificate_count"),
    ("Browser Extensions", "browser_extension_count"),
    ("Installed Packages", "installed_package_count"),
)


def _match_basis(row: dict) -> str:
    """Name the match basis: these rows come only from NVD CPE matches (match_tier 'cpe')."""
    cpes = row.get("cpe")
    names = [str(item) for item in cpes] if isinstance(cpes, list) else [str(cpes or "")]
    names = [name for name in names if name]
    return "NVD CPE " + ", ".join(names) if names else "NVD CPE"


def format_cve_match_table(rows: list[dict], columns: ColumnSpec) -> str:
    """CVE rows with their match basis as the last column."""
    table_rows = [
        [escape_table_cell(row.get(key, default)) for _, key, default in columns]
        + [escape_table_cell(_match_basis(row))]
        for row in rows
    ]
    headers = [header for header, _, _ in columns] + ["Match basis"]
    return tabulate(table_rows, headers=headers, tablefmt="github")


def host_inventory_metadata_rows(metadata: dict) -> list[list[str]]:
    """Inventory counts present in the metadata (only the scan JSON path provides them)."""
    return [
        [label, str(metadata[key])] for label, key in _INVENTORY_METADATA_ROWS if key in metadata
    ]


def _error_sources(metadata: dict) -> set[str]:
    """Collector error sources without the ``" (count)"`` suffix the import adds."""
    sources = metadata.get("collection_error_sources")
    if not isinstance(sources, list):
        return set()
    return {re.sub(r" \(\d+\)$", "", str(source)) for source in sources}


def _int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _installed_cve_line(rows: list[dict]) -> str | None:
    if not rows:
        return None
    cves = sum(_int(row.get("cve_count")) for row in rows)
    kev = sum(_int(row.get("kev_count")) for row in rows)
    return (
        f"Installed software with NVD-matched CVEs: {len(rows)} app(s), "
        f"{cves} CVE match(es) ({kev} in KEV)"
    )


def _macos_cve_lines(rows: list[dict]) -> list[str]:
    return [
        f"macOS {escape_report_value(row.get('macos_version') or 'unknown')}: "
        f"{_int(row.get('cve_count'))} CVE(s) ({_int(row.get('kev_count'))} in KEV)"
        for row in rows
    ]


def _firewall_state(rows: list[dict]) -> str:
    states = {row.get("firewall_enabled") for row in rows}
    if states == {False}:
        return "application firewall off"
    if states == {True}:
        return "application firewall on"
    return "application firewall state not collected"


def _listener_line(rows: list[dict]) -> str | None:
    if not rows:
        return None
    exposed = [row for row in rows if row.get("exposed") is True]
    unfiltered = sum(1 for row in exposed if row.get("reachable_without_firewall") is True)
    if not exposed:
        return f"Exposed network listeners: 0 of {len(rows)} (all bound to loopback)"
    return (
        f"Exposed network listeners: {len(exposed)} of {len(rows)} "
        f"({_firewall_state(exposed)}; {unfiltered} reachable without a firewall)"
    )


def _counted_line(label: str, count: int) -> str | None:
    return f"{label}: {count}" if count else None


def _summary_candidates(query_results: dict[str, list[dict] | str]) -> list[tuple[str, list[str]]]:
    """(error source key, lines) per summary topic; an empty list means no rows."""
    trusted = query_rows(query_results, "107-custom-trusted-root-cas.cypher")
    custom_roots = sum(1 for row in trusted if row.get("custom_root") is True)
    extensions = query_rows(query_results, "108-risky-browser-extensions.cypher")
    dyld = query_rows(query_results, "109-launchd-environment-injection.cypher")
    candidates = [
        (_NO_SOURCE, [_installed_cve_line(query_rows(query_results, _Q104))]),
        (_NO_SOURCE, _macos_cve_lines(query_rows(query_results, _Q105))),
        ("listeners", [_listener_line(query_rows(query_results, _Q106))]),
        ("trust", [_counted_line("Custom root CAs trusted", custom_roots)]),
        (
            "extensions",
            [
                _counted_line(
                    "Browser extensions with broad site access or sideloaded", len(extensions)
                )
            ],
        ),
        (_NO_SOURCE, [_counted_line("Launch items with DYLD injection", len(dyld))]),
    ]
    return [(source, [line for line in lines if line]) for source, lines in candidates]


_NOT_COLLECTED = {
    "listeners": "Network listeners: not collected (the collector recorded errors)",
    "trust": "Trusted certificates: not collected (the collector recorded errors)",
    "extensions": "Browser extensions: not collected (the collector recorded errors)",
}


def host_evidence_summary_lines(
    query_results: dict[str, list[dict] | str], metadata: dict
) -> list[str]:
    """Executive-summary bullets for host evidence, omitted when nothing was found."""
    failed = _error_sources(metadata)
    lines: list[str] = []
    for source, found in _summary_candidates(query_results):
        failed_source = _ERROR_SOURCES.get(source) in failed
        if found:
            suffix = " (collection incomplete)" if failed_source else ""
            lines.extend(f"- {line}{suffix}" for line in found)
        elif failed_source:
            lines.append(f"- {_NOT_COLLECTED[source]}")
    return ["**Host evidence:**", *lines, ""] if lines else []
