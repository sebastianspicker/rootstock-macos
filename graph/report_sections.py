"""Extended report sections and attack-context mapping helpers."""

from __future__ import annotations

from query_runner import find_query
from report_diagrams import (
    mermaid_icloud_risk_flow,
    mermaid_posture_summary,
    mermaid_tier_pie,
)
from cve_reference import get_context
from report_formatters import (
    format_generic_table,
    format_no_findings,
    format_vulnerability_summary,
)


def _section_for_queries(
    query_results: dict[str, list[dict] | str],
    query_ids: list[str],
    queries: list[dict],
) -> str:
    """Format results from multiple queries, each under its own sub-heading."""
    parts: list[str] = []
    for qid in query_ids:
        q = find_query(queries, qid)
        if q is None:
            continue
        result = query_results.get(q["filename"], [])
        name = q.get("name", q["filename"])
        parts.append(f"#### Query {qid}: {name}")
        if isinstance(result, str):
            parts.append(f"> **Error:** {result}")
        elif not result:
            parts.append(format_no_findings())
        else:
            parts.append(format_generic_table(result))
        parts.append("")
    return "\n".join(parts)


def _build_vulnerability_section(active_categories: set[str]) -> str:
    """Build the Top Vulnerabilities & ATT&CK Mapping section from active categories."""
    contexts = []
    for cat in sorted(active_categories):
        ctx = get_context(cat)
        if ctx is not None:
            contexts.append(ctx)
    if not contexts:
        return ""
    return format_vulnerability_summary(contexts)


def _get_query_rows(
    query_results: dict[str, list[dict] | str],
    filename: str,
) -> list[dict]:
    result = query_results.get(filename, [])
    return result if isinstance(result, list) else []


def _has_any_query_rows(
    query_results: dict[str, list[dict] | str],
    *filenames: str,
) -> bool:
    return any(_get_query_rows(query_results, filename) for filename in filenames)


def _append_titled_query_section(
    sections: list[str],
    title: str,
    risk_text: str,
    query_ids: list[str],
    query_results: dict[str, list[dict] | str],
    queries: list[dict],
) -> None:
    sections.append(title)
    sections.append(risk_text)
    sections.append("")
    sections.append(_section_for_queries(query_results, query_ids, queries))
    sections.append("")


def _append_extended_query_sections(
    sections: list[str],
    query_results: dict[str, list[dict] | str],
    queries: list[dict],
    tier_counts: dict[str, int],
    icloud_rows_68: list[dict],
) -> None:
    _append_static_extended_query_sections(sections, query_results, queries)
    _append_physical_posture_section(sections, query_results, queries)
    _append_icloud_risk_section(sections, query_results, queries, icloud_rows_68)
    _append_tier_classification_section(sections, query_results, queries, tier_counts)


def _append_static_extended_query_sections(
    sections: list[str],
    query_results: dict[str, list[dict] | str],
    queries: list[dict],
) -> None:
    for title, risk_text, query_ids in _extended_section_specs():
        _append_titled_query_section(
            sections,
            title,
            risk_text,
            query_ids,
            query_results,
            queries,
        )


def _extended_section_specs() -> list[tuple[str, str, list[str]]]:
    return [
        (
            "## Advanced Attack Paths: Injection Chains & XPC Escalation",
            "> **Risk:** Multi-hop injection chains, XPC services without client verification, "
            "and sandbox escape paths allow attackers to escalate privileges beyond direct "
            "TCC injection. These paths often bypass single-layer defences.",
            ["11", "13", "15", "30"],
        ),
        (
            "## Code Signing & Certificate Risk",
            "> **Risk:** Apps signed with expired certificates, ad-hoc signatures, or "
            "non-Apple CA chains have weaker trust guarantees. If these apps hold TCC "
            "grants, an attacker can more easily forge or replace them.",
            ["37", "60", "61", "62"],
        ),
        (
            "## Persistence & Hijack Risk",
            "> **Risk:** Hijackable LaunchDaemons, writable shell hooks, and unconstrained "
            "injectable services provide persistent footholds. An attacker who compromises "
            "these can survive reboots and maintain access indefinitely.",
            ["29", "50", "51"],
        ),
        (
            "## Authorization & Privilege Escalation",
            "> **Risk:** Admin group membership, weak authorization rights, sudoers NOPASSWD "
            "rules, and group-based capability escalation can grant an attacker root or "
            "near-root privileges without exploiting any vulnerability.",
            ["24", "33", "36", "58"],
        ),
        (
            "## File System & ACL Risk",
            "> **Risk:** Writable security-critical files (TCC.db, sudoers, sshd_config, "
            "LaunchDaemon directories) enable direct privilege escalation. File ACLs that "
            "grant write access to non-root users are high-priority findings.",
            ["48", "49"],
        ),
    ]


def _append_physical_posture_section(
    sections: list[str],
    query_results: dict[str, list[dict] | str],
    queries: list[dict],
) -> None:
    posture_rows = _get_query_rows(
        query_results, "67-physical-security-overview.cypher"
    )
    _append_titled_query_section(
        sections,
        "## Physical & Remote Access Posture",
        "> **Risk:** Weak physical security posture (disabled screen lock, Thunderbolt "
        "in no-security mode, Lockdown Mode off) combined with enabled remote access "
        "services expands the attack surface to local and network-adjacent attackers.",
        ["25", "64", "67"],
        query_results,
        queries,
    )
    if posture_rows:
        sections.append("### Physical Security Posture Diagram")
        sections.append(mermaid_posture_summary(posture_rows))
    sections.append("")


def _append_icloud_risk_section(
    sections: list[str],
    query_results: dict[str, list[dict] | str],
    queries: list[dict],
    icloud_rows_68: list[dict],
) -> None:
    _append_titled_query_section(
        sections,
        "## Cloud & iCloud Risk",
        "> **Risk:** Injectable applications with iCloud container entitlements can "
        "exfiltrate data via iCloud sync to all devices enrolled in the same Apple ID. "
        "iCloud Keychain sync exposes credentials across the device fleet.",
        ["68", "69", "70"],
        query_results,
        queries,
    )
    if icloud_rows_68:
        sections.append("### iCloud Risk Flow Diagram")
        sections.append(mermaid_icloud_risk_flow(icloud_rows_68))
    sections.append("")


def _append_tier_classification_section(
    sections: list[str],
    query_results: dict[str, list[dict] | str],
    queries: list[dict],
    tier_counts: dict[str, int],
) -> None:
    _append_titled_query_section(
        sections,
        "## Tier Classification Overview",
        "> Tier 0 assets are the crown jewels — apps with Full Disk Access, "
        "Accessibility, or Screen Recording grants that are injectable. Tier 1 "
        "apps hold moderate TCC grants. Tier 2 is everything else.",
        ["46", "57"],
        query_results,
        queries,
    )
    if tier_counts:
        sections.append("### Tier Distribution")
        sections.append(mermaid_tier_pie(tier_counts))
    sections.append("")


def _fallback_attack_categories(
    query_results: dict[str, list[dict] | str],
    injectable_rows: list[dict],
    electron_rows: list[dict],
    apple_event_rows: list[dict],
    icloud_rows: tuple[list[dict], list[dict], list[dict]],
    cert_rows: tuple[list[dict], list[dict], list[dict]],
) -> set[str]:
    state = {
        "injectable_rows": injectable_rows,
        "electron_rows": electron_rows,
        "apple_event_rows": apple_event_rows,
        "icloud_rows": icloud_rows,
        "cert_rows": cert_rows,
    }
    active_categories: set[str] = set()
    for categories, condition in _fallback_category_conditions(query_results, state):
        if condition:
            active_categories.update(categories)
    return active_categories


def _fallback_category_conditions(
    query_results: dict[str, list[dict] | str],
    state: dict[str, object],
) -> list[tuple[tuple[str, ...], bool]]:
    return (
        _primary_fallback_category_conditions(query_results, state)
        + _posture_fallback_category_conditions(query_results, state)
        + _endpoint_fallback_category_conditions(query_results, state)
    )


PRIMARY_QUERY_CATEGORY_QUERIES: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("persistence_hijack",), ("29-hijackable-launch-daemons.cypher",)),
    (("xpc_exploitation",), ("30-xpc-no-client-verification.cypher",)),
    (("accessibility_abuse",), ("54-accessibility-abuse.cypher",)),
    (
        ("keychain_access",),
        ("40-injectable-shared-keychain.cypher", "59-keychain-crown-jewels.cypher"),
    ),
    (("kerberos",), ("73-kerberos-ticket-theft.cypher",)),
    (("physical_security",), ("64-weak-physical-posture.cypher",)),
    (
        ("authorization_hardening",),
        (
            "24-admin-group-escalation.cypher",
            "33-weak-authorization-rights.cypher",
            "36-sudoers-nopasswd.cypher",
        ),
    ),
    (("shell_hooks",), ("50-shell-hook-injection.cypher",)),
)


def _query_fallback_category_conditions(
    query_results: dict[str, list[dict] | str],
    category_queries: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...],
) -> list[tuple[tuple[str, ...], bool]]:
    return [
        (categories, _has_any_query_rows(query_results, *queries))
        for categories, queries in category_queries
    ]


def _primary_fallback_category_conditions(
    query_results: dict[str, list[dict] | str],
    state: dict[str, object],
) -> list[tuple[tuple[str, ...], bool]]:
    return [
        (("injectable_fda", "dyld_injection"), bool(state["injectable_rows"])),
        (("electron_inheritance",), bool(state["electron_rows"])),
        (("apple_events", "tcc_bypass"), bool(state["apple_event_rows"])),
        (("icloud_risk",), any(state["icloud_rows"])),
    ] + _query_fallback_category_conditions(query_results, PRIMARY_QUERY_CATEGORY_QUERIES)


def _posture_fallback_category_conditions(
    query_results: dict[str, list[dict] | str],
    state: dict[str, object],
) -> list[tuple[tuple[str, ...], bool]]:
    return [
        (
            ("file_acl_escalation",),
            _has_any_query_rows(
                query_results,
                "48-file-acl-write-paths.cypher",
                "49-file-permission-escalation.cypher",
            ),
        ),
        (
            ("esf_bypass",),
            _has_any_query_rows(
                query_results,
                "55-injectable-esf-client.cypher",
                "56-injectable-network-extension.cypher",
            ),
        ),
        (
            ("sandbox_escape",),
            _has_any_query_rows(query_results, "27-sandbox-escape-risk.cypher"),
        ),
        (
            ("mdm_risk",),
            _has_any_query_rows(
                query_results, "10-mdm-managed-tcc.cypher", "39-mdm-overgrant.cypher"
            ),
        ),
        (
            ("lateral_movement",),
            _has_any_query_rows(
                query_results,
                "25-remote-access-surface.cypher",
                "52-cross-host-user.cypher",
                "53-cross-host-injection-chain.cypher",
            ),
        ),
    ]


def _endpoint_fallback_category_conditions(
    query_results: dict[str, list[dict] | str],
    state: dict[str, object],
) -> list[tuple[tuple[str, ...], bool]]:
    return [
        (
            ("running_processes",),
            _has_any_query_rows(query_results, "38-running-injectable-with-tcc.cypher"),
        ),
        (("certificate_hygiene",), any(state["cert_rows"])),
        (
            ("auth_plugin_risk",),
            _has_any_query_rows(query_results, "34-non-apple-auth-plugins.cypher"),
        ),
        (
            ("firewall_exposure",),
            _has_any_query_rows(query_results, "28-firewall-exposed-injectable.cypher"),
        ),
        (
            ("gatekeeper_bypass",),
            _has_any_query_rows(
                query_results,
                "88-unquarantined-apps.cypher",
                "89-quarantine-bypass-with-tcc.cypher",
            ),
        ),
    ]


def _collect_active_categories(
    query_results: dict[str, list[dict] | str],
    injectable_rows: list[dict],
    electron_rows: list[dict],
    apple_event_rows: list[dict],
    icloud_rows: tuple[list[dict], list[dict], list[dict]],
    cert_rows: tuple[list[dict], list[dict], list[dict]],
) -> set[str]:
    active_categories: set[str] = set()
    for row in _get_query_rows(query_results, "95-high-risk-apps.cypher"):
        cats = row.get("attack_categories")
        if isinstance(cats, list):
            active_categories.update(cats)
    if active_categories:
        return active_categories
    return _fallback_attack_categories(
        query_results,
        injectable_rows,
        electron_rows,
        apple_event_rows,
        icloud_rows,
        cert_rows,
    )


def _append_vulnerability_mapping(
    sections: list[str],
    active_categories: set[str],
) -> None:
    vuln_section = _build_vulnerability_section(active_categories)
    if not vuln_section:
        return
    sections.append("## Top Vulnerabilities & ATT&CK Mapping")
    sections.append(
        "> CVE references and MITRE ATT&CK techniques relevant to findings on this host."
    )
    sections.append("")
    sections.append(vuln_section)
    sections.append("")


def _append_threat_landscape(
    sections: list[str],
    query_results: dict[str, list[dict] | str],
) -> None:
    threat_rows = _get_query_rows(query_results, "92-apt-group-exposure.cypher")
    if not threat_rows:
        return
    sections.append("## Threat Landscape: APT Group Exposure")
    sections.append(
        "> APT groups whose techniques are relevant to vulnerabilities found on this host."
    )
    sections.append("")
    sections.append(format_generic_table(threat_rows))
    sections.append("")
