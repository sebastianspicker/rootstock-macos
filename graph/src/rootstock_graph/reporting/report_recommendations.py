"""Recommendation section assembly for Rootstock reports.

The graph is the source of truth: ``rootstock-graph-infer`` attaches
``Recommendation`` nodes to applications and to the host, and query 100 lists
them with the names they apply to. The report prints those rows, grouped by
priority, so the advice matches the evidence. When the graph carries no
recommendations (for example a snapshot imported without inference), a short
static catalogue keyed by the report's own findings is printed instead.
"""

from __future__ import annotations


from .report_formatters import escape_report_value
from .report_query_results import query_rows

_PRIORITY_ORDER = ("critical", "high", "medium", "low")
_PRIORITY_HEADINGS = {
    "critical": "Critical: fix now",
    "high": "High: fix soon",
    "medium": "Medium: review",
    "low": "Low: good hygiene",
}
_MAX_NAMES = 8

# ── Static fallback catalogue ─────────────────────────────────────────────────

RECOMMENDATIONS = {
    "injectable_fda": [
        "Review every app that holds Full Disk Access (System Settings › Privacy & Security › Full Disk Access) and remove the grant from apps that code can be loaded into.",
        "Update apps that lack Hardened Runtime or Library Validation, or ask their vendors for hardened builds. [ref: CVE-2024-44168]",
    ],
    "electron_inheritance": [
        "Update Electron apps whose RunAsNode fuse is enabled; until the vendor disables it, keep them away from Full Disk Access, Accessibility and Screen Recording. [ref: CVE-2023-44402]",
    ],
    "apple_events": [
        "Remove Automation permission (System Settings › Privacy & Security › Automation) from apps that do not need to control other apps. [ref: CVE-2024-44206]",
    ],
    "physical_security": [
        "Turn on FileVault and require a password within 5 seconds of sleep or screen saver.",
        "Keep Startup Security at Full and leave booting from external media disabled unless you need it.",
    ],
    "certificate_hygiene": [
        "Replace unsigned or ad-hoc-signed apps with Developer ID builds, and confirm the origin of apps that Gatekeeper reports as not notarized.",
    ],
    "icloud_risk": [
        "Review iCloud container entitlements on injectable apps; injected code can sync data to every device on the Apple ID.",
    ],
    "authorization_hardening": [
        "Remove NOPASSWD from sudoers rules with `sudo visudo`. [ref: T1548.003]",
        "Review non-Apple authorization plugins in /Library/Security/SecurityAgentPlugins.",
    ],
    "shell_hooks": [
        "Set shell start-up files (.zshrc, .zprofile, /etc/zshrc) to owner-only write; anything written there runs in every new terminal. [ref: CVE-2023-32364]",
    ],
    "file_acl_escalation": [
        "Restore root:wheel ownership and remove write bits or ACL entries on sudoers, LaunchDaemons, the authorization database and sshd_config.",
    ],
    "esf_bypass": [
        "Update security tools that are injectable and report the missing hardening to the vendor; a blinded Endpoint Security client hides later activity. [ref: CVE-2024-27842]",
    ],
    "sandbox_escape": [
        "Update sandboxed apps that combine broad sandbox exceptions with injectability, and review whether they need those exceptions.",
    ],
    "mdm_risk": [
        "Ask the MDM administrator to scope PPPC payloads so terminals and script interpreters do not receive Full Disk Access or Accessibility. [ref: CVE-2024-44301]",
    ],
    "lateral_movement": [
        "Turn off Remote Login and Screen Sharing in System Settings › General › Sharing unless you use them; if you do, restrict them to specific users and disable SSH password authentication. [ref: T1021.004]",
    ],
    "running_processes": [
        "Prioritise updating injectable apps that were running during the scan; they are live targets.",
    ],
    "gatekeeper_bypass": [
        "Confirm where apps without a quarantine record and without notarization came from before granting them permissions. [ref: CVE-2022-42821]",
    ],
    "general": [
        "Keep System Integrity Protection and Gatekeeper enabled (`csrutil status`, `spctl --status`).",
        "Review LaunchDaemons and LaunchAgents periodically and remove items from software you no longer use.",
        "Rerun Rootstock after major installs or macOS updates and compare the reports.",
    ],
}


def _has_any_query_rows(
    query_results: dict[str, list[dict] | str],
    *filenames: str,
) -> bool:
    return any(query_rows(query_results, filename) for filename in filenames)


def _append_recommendations(
    sections: list[str],
    heading: str,
    key: str,
    condition: bool,
) -> None:
    """Conditionally append a recommendation block to the report sections."""
    if not condition:
        return
    sections.append(f"### {heading}")
    for rec in RECOMMENDATIONS[key]:
        sections.append(f"- {rec}")
    sections.append("")


# ── Graph-driven section ──────────────────────────────────────────────────────


def _names(row: dict) -> str:
    names = row.get("affected_names")
    if not isinstance(names, list) or not names:
        return ""
    shown = ", ".join(escape_report_value(name) for name in names[:_MAX_NAMES])
    extra = int(row.get("affected_count") or len(names)) - min(len(names), _MAX_NAMES)
    return shown + (f" and {extra} more" if extra > 0 else "")


def _graph_recommendation_lines(row: dict) -> list[str]:
    title = escape_report_value(
        row.get("title") or row.get("recommendation_key") or "Recommendation"
    )
    text = escape_report_value(row.get("recommendation") or "")
    scope = "Host setting" if row.get("scope") == "host" else "Applies to"
    lines = [f"- **{title}** — {text}"]
    names = _names(row)
    if names:
        lines.append(f"  - {scope}: {names}")
    techniques = row.get("mitigates_techniques")
    if isinstance(techniques, list) and techniques:
        lines.append(
            "  - Mitigates: " + ", ".join(escape_report_value(item) for item in techniques)
        )
    return lines


def append_graph_recommendations(
    sections: list[str],
    recommendation_rows: list[dict],
) -> bool:
    """Print the graph's recommendations grouped by priority. Returns False when none exist."""
    rows = [row for row in recommendation_rows if isinstance(row, dict)]
    if not rows:
        return False
    sections.append(
        "> Each item names the setting or action for the person administering this Mac, "
        "and the apps or host it applies to. Priorities come from the modeled exposure."
    )
    sections.append("")
    for priority in _PRIORITY_ORDER:
        group = [row for row in rows if str(row.get("priority", "")).lower() == priority]
        if not group:
            continue
        sections.append(f"### {_PRIORITY_HEADINGS[priority]}")
        for row in group:
            sections.extend(_graph_recommendation_lines(row))
        sections.append("")
    return True


def append_recommendations_section(
    sections: list[str],
    query_results: dict[str, list[dict] | str],
    rows: object,
) -> None:
    sections.append("## Recommendations")
    if append_graph_recommendations(
        sections, query_rows(query_results, "100-top-recommendations.cypher")
    ):
        return
    sections.append(
        "> No graph recommendations were recorded (run `rootstock-graph-infer` after import). "
        "The guidance below is selected from the report's own findings."
    )
    sections.append("")
    state = {
        "injectable_rows": rows.injectable,
        "electron_rows": rows.electron,
        "apple_event_rows": rows.apple_event,
        "posture_rows_64": query_rows(query_results, "64-weak-physical-posture.cypher"),
        "icloud_rows": rows.icloud,
        "cert_rows": rows.certificate,
    }
    for heading, key, condition in _recommendation_conditions(query_results, state):
        _append_recommendations(sections, heading, key, condition)

    sections.append("### General macOS Hardening")
    for rec in RECOMMENDATIONS["general"]:
        sections.append(f"- {rec}")
    sections.append("")


def _recommendation_conditions(
    query_results: dict[str, list[dict] | str],
    state: dict[str, object],
) -> list[tuple[str, str, bool]]:
    return (
        _primary_recommendation_conditions(state)
        + _privilege_recommendation_conditions(query_results)
        + _endpoint_recommendation_conditions(query_results)
    )


def _primary_recommendation_conditions(
    state: dict[str, object],
) -> list[tuple[str, str, bool]]:
    return [
        (
            "Injectable Applications with Privileged TCC Grants",
            "injectable_fda",
            bool(state["injectable_rows"]),
        ),
        (
            "Electron Application Hardening",
            "electron_inheritance",
            bool(state["electron_rows"]),
        ),
        (
            "Apple Event Automation Hygiene",
            "apple_events",
            bool(state["apple_event_rows"]),
        ),
        (
            "Physical Security Hardening",
            "physical_security",
            bool(state["posture_rows_64"]),
        ),
        ("Certificate Hygiene", "certificate_hygiene", any(state["cert_rows"])),
        ("iCloud Risk Mitigation", "icloud_risk", any(state["icloud_rows"])),
    ]


def _privilege_recommendation_conditions(
    query_results: dict[str, list[dict] | str],
) -> list[tuple[str, str, bool]]:
    return [
        (
            "Authorization Hardening",
            "authorization_hardening",
            _has_any_query_rows(
                query_results,
                "24-admin-group-escalation.cypher",
                "33-weak-authorization-rights.cypher",
                "36-sudoers-nopasswd.cypher",
                "58-group-capability-escalation.cypher",
            ),
        ),
        (
            "Shell Hook Hardening",
            "shell_hooks",
            _has_any_query_rows(query_results, "50-shell-hook-injection.cypher"),
        ),
        (
            "File ACL Escalation Mitigation",
            "file_acl_escalation",
            _has_any_query_rows(
                query_results,
                "48-file-acl-write-paths.cypher",
                "49-file-permission-escalation.cypher",
            ),
        ),
        (
            "Endpoint Security Framework Protection",
            "esf_bypass",
            _has_any_query_rows(
                query_results,
                "55-injectable-esf-client.cypher",
                "56-injectable-network-extension.cypher",
            ),
        ),
    ]


def _endpoint_recommendation_conditions(
    query_results: dict[str, list[dict] | str],
) -> list[tuple[str, str, bool]]:
    return [
        (
            "Sandbox Escape Mitigation",
            "sandbox_escape",
            _has_any_query_rows(query_results, "27-sandbox-escape-risk.cypher"),
        ),
        (
            "MDM Configuration Hygiene",
            "mdm_risk",
            _has_any_query_rows(
                query_results, "10-mdm-managed-tcc.cypher", "39-mdm-overgrant.cypher"
            ),
        ),
        (
            "Lateral Movement Mitigation",
            "lateral_movement",
            _has_any_query_rows(
                query_results,
                "25-remote-access-surface.cypher",
                "52-cross-host-user.cypher",
                "53-cross-host-injection-chain.cypher",
            ),
        ),
        (
            "Running Process Hardening",
            "running_processes",
            _has_any_query_rows(query_results, "38-running-injectable-with-tcc.cypher"),
        ),
        (
            "Gatekeeper Bypass Mitigation",
            "gatekeeper_bypass",
            _has_any_query_rows(
                query_results,
                "88-unquarantined-apps.cypher",
                "89-quarantine-bypass-with-tcc.cypher",
            ),
        ),
    ]
