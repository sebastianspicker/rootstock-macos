"""Host evidence report sections: NVD matches, network, trust store, extensions, persistence detail."""

from __future__ import annotations

from .query_runner import find_query
from .report_formatters import format_no_findings
from .report_formatters_host import (
    INSTALLED_CVE_COLUMNS,
    MACOS_CVE_COLUMNS,
    format_cve_match_table,
)
from .report_sections import append_titled_query_section

__all__ = ["append_host_evidence_sections"]

_CVE_QUERIES = (("104", INSTALLED_CVE_COLUMNS), ("105", MACOS_CVE_COLUMNS))


def _host_section_specs() -> list[tuple[str, str, list[str]]]:
    return [
        (
            "## CVE Coverage and Candidates",
            "> NVD candidates have unresolved conditions or stale, incomplete, or legacy cache evidence. "
            "They are excluded from version-match risk scoring. Missing coverage is not a clean bill of health.",
            ["119", "120"],
        ),
        (
            "## Network Exposure",
            "> Evidence: These sockets are bound to non-loopback addresses. Remote reachability "
            "depends on routing, application behavior and local or upstream filtering; disabling "
            "the application firewall alone does not prove a service is reachable.",
            ["106", "116"],
        ),
        (
            "## Trust Store",
            "> Risk: A root certificate added to the user or admin trust settings can sign "
            "certificates for any website. Whoever holds its private key can intercept TLS "
            "traffic from this Mac without a browser warning. Corporate inspection roots are "
            "expected on managed Macs; confirm each one is yours.",
            ["107"],
        ),
        (
            "## Browser Extensions",
            "> Risk: Extensions that can read and change every site see passwords, session "
            "cookies and page content. Extensions loaded unpacked or side-loaded from outside "
            "the store skipped store review.",
            ["108"],
        ),
        (
            "## Persistence Detail",
            "> Evidence: Launch items can record custom loader settings, missing programs and "
            "writable paths. Verify the job's identity, effective permissions and loaded state; "
            "these observations alone do not establish code execution or tampering.",
            ["109", "110", "111", "112", "113"],
        ),
        (
            "## Host Security Settings",
            "> Risk: Guest access, automatic login, an enabled root account and remote "
            "control services weaken the Mac directly; disabled automatic security updates "
            "leave known vulnerabilities in place. DNS, proxy and hosts-file overrides decide "
            "where network traffic goes. Settings the collector could not read are shown as "
            "unknown, never as safe.",
            ["117", "118"],
        ),
        (
            "## Processes",
            "> Risk: A process whose executable lives in a temporary folder, /Users/Shared or "
            "a user's Library, Downloads, Desktop or Documents folder runs code an ordinary "
            "user could have replaced. This is a snapshot of what was running at scan time.",
            ["115"],
        ),
    ]


def _cve_query_part(
    query_results: dict[str, list[dict] | str], queries: list[dict], query_id: str, columns
) -> list[str]:
    query = find_query(queries, query_id)
    if query is None:
        return []
    result = query_results.get(query["filename"], [])
    parts = [f"#### Query {query_id}: {query.get('name', query['filename'])}"]
    if isinstance(result, str):
        parts.append(f"> Error: {result}")
    elif not result:
        parts.append(format_no_findings())
    else:
        parts.append(format_cve_match_table(result, columns))
    return [*parts, ""]


def _append_installed_software_cves(
    sections: list[str], query_results: dict[str, list[dict] | str], queries: list[dict]
) -> None:
    sections.append("## Installed Software Vulnerabilities (NVD)")
    sections.append(
        "> Risk: These CVEs were matched against the exact installed version through NVD "
        "CPE lookups. A matched CVE is a published weakness in that version, not evidence "
        "that it was exploited on this Mac. Registry matches from Rootstock's curated "
        "catalogue are listed separately (Query 85); this section lists NVD matches only."
    )
    sections.append("")
    for query_id, columns in _CVE_QUERIES:
        sections.extend(_cve_query_part(query_results, queries, query_id, columns))
    sections.append("")


def append_host_evidence_sections(
    sections: list[str],
    query_results: dict[str, list[dict] | str],
    queries: list[dict],
) -> None:
    """Append the host evidence sections in their stable report order."""
    _append_installed_software_cves(sections, query_results, queries)
    for title, risk_text, query_ids in _host_section_specs():
        append_titled_query_section(sections, title, risk_text, query_ids, query_results, queries)
