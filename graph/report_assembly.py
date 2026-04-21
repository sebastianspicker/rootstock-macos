"""report_assembly.py — Report assembly, recommendations, and HTML conversion."""

from __future__ import annotations

import html as html_mod
import socket
from datetime import datetime, timezone

from tabulate import tabulate

from query_runner import discover_queries, find_query
from report_diagrams import (
    mermaid_attack_paths_block,
    mermaid_tcc_pie,
    mermaid_tier_pie,
    mermaid_posture_summary,
    mermaid_icloud_risk_flow,
)
from utils import list_or_str
from cve_reference import get_context
from report_formatters import (
    format_no_findings,
    format_generic_table,
    format_injectable_fda_table,
    format_electron_table,
    format_apple_event_table,
    format_tcc_overview_table,
    format_private_entitlement_table,
    format_executive_summary,
    format_vulnerability_summary,
)


# ── Recommendations ───────────────────────────────────────────────────────────

RECOMMENDATIONS = {
    "injectable_fda": [
        "Enable Hardened Runtime for all first-party and in-house applications via the entitlements editor in Xcode.",
        "Enable Library Validation (`com.apple.security.cs.require-library-validation`) to prevent unsigned dylib injection. [ref: CVE-2024-44168]",
        "Audit all applications with Full Disk Access — revoke unnecessary grants via System Settings → Privacy & Security → Full Disk Access.",
        "Use `codesign --verify --deep --strict` in CI/CD pipelines to catch hardened-runtime regressions before release.",
    ],
    "electron_inheritance": [
        "Disable `ELECTRON_RUN_AS_NODE` support in production Electron builds by passing `--disable-node-options` or using `app.commandLine.appendSwitch`. [ref: CVE-2023-44402]",
        "Sandbox Electron apps using macOS App Sandbox where feasible to limit the blast radius of ELECTRON_RUN_AS_NODE abuse.",
        "Apply least privilege: Electron apps should not hold TCC permissions they don't actively need; request only what is strictly required.",
    ],
    "apple_events": [
        "Audit Apple Event automation grants in TCC — revoke `kTCCServiceAppleEvents` grants to low-trust or injectable apps. [ref: CVE-2024-44206]",
        "Implement Apple Event permission review as part of quarterly access reviews alongside FDA and Accessibility grants.",
    ],
    "physical_security": [
        "Enable Lockdown Mode on high-value targets to reduce the attack surface from zero-click exploits and hardware interfaces. [ref: CVE-2023-42861]",
        "Configure automatic screen lock with a delay of 60 seconds or less to prevent physical-access exploitation.",
        "Review Thunderbolt security level — set to `full` security to require user approval for Thunderbolt/USB4 peripherals.",
        "Enable FileVault full-disk encryption on all endpoints to protect data at rest from physical theft.",
    ],
    "certificate_hygiene": [
        "Require notarization for all in-house applications before deployment to ensure Apple has scanned for known malware.",
        "Monitor for expired signing certificates on applications with active TCC grants — expired certs weaken trust validation.",
        "Audit non-Apple CA chains in your application inventory — these may indicate repackaged or enterprise-signed software with elevated risk.",
    ],
    "icloud_risk": [
        "Review iCloud container entitlements on injectable applications — injected code can exfiltrate data via iCloud sync to all user devices.",
        "Consider disabling iCloud Drive on high-security endpoints where synced data could create a cross-device exfiltration path.",
        "Audit iCloud Keychain sync on endpoints with sensitive credentials — synced keychain items are accessible on all enrolled devices.",
    ],
    "authorization_hardening": [
        "Audit sudoers NOPASSWD entries — remove unnecessary passwordless sudo rules that allow privilege escalation without authentication. [ref: T1548.003]",
        "Review non-Apple authorization plugins in `/Library/Security/SecurityAgentPlugins/` — third-party plugins execute in the authorization flow.",
        "Harden weak authorization rights that use `allow` or `authenticate-session-owner` rules for sensitive operations.",
    ],
    "shell_hooks": [
        "Audit writable shell configuration files (.zshrc, .bashrc, .zprofile) — restrict write access to the owning user only. [ref: CVE-2023-32364]",
        "Deploy file integrity monitoring on shell hook files to detect unauthorised modifications that could inject keyloggers or credential harvesters.",
    ],
    "file_acl_escalation": [
        "Audit file ACLs on security-critical files (TCC.db, sudoers, sshd_config) — remove non-root write ACEs. [ref: CVE-2024-23296]",
        "Implement periodic ACL scanning to detect privilege creep on LaunchDaemon directories and authorization databases.",
    ],
    "esf_bypass": [
        "Harden injectable apps with ESF entitlements — these can blind EDR and security monitoring if compromised. [ref: CVE-2024-27842]",
        "Monitor for anomalous ESF client registrations and network extension loads that may indicate tampered security tools.",
    ],
    "sandbox_escape": [
        "Prioritise patching sandbox escape CVEs (CVE-2023-32414, CVE-2023-38606) — sandbox escapes enable full system access from app-level compromise.",
        "Audit unsandboxed injectable apps and consider deploying App Sandbox for in-house tools where feasible.",
    ],
    "mdm_risk": [
        "Review MDM PPPC profiles for overgrants — ensure scripting interpreters (Python, Ruby, osascript) do not hold FDA or Accessibility grants via MDM. [ref: CVE-2024-44301]",
        "Implement MDM profile change auditing to detect unauthorized TCC grant modifications.",
    ],
    "lateral_movement": [
        "Restrict SSH and Screen Sharing access to authorised users via MDM or `/etc/ssh/sshd_config` AllowUsers/AllowGroups directives. [ref: T1021.004]",
        "Audit cross-host user accounts — shared credentials across hosts enable lateral movement after initial compromise.",
    ],
    "running_processes": [
        "Monitor running injectable processes with active TCC grants — these are live exploitation targets. [ref: CVE-2025-24085]",
        "Implement runtime injection detection (e.g., DYLD_INSERT_LIBRARIES monitoring) for high-value processes.",
    ],
    "gatekeeper_bypass": [
        "Investigate unquarantined non-system applications — these bypassed Gatekeeper download checks. [ref: CVE-2022-42821, CVE-2024-44175]",
        "Enable Gatekeeper enforcement via `spctl --master-enable` on all endpoints.",
        "Review apps without quarantine attributes that hold TCC grants for potential Gatekeeper bypass abuse.",
    ],
    "general": [
        "Ensure System Integrity Protection (SIP) is enabled on all managed endpoints (`csrutil status`).",
        "Enforce Full Disk Access via MDM Privacy Preferences Policy Control (PPPC) profiles — maintain an allow-list of approved applications.",
        "Review all LaunchDaemons and LaunchAgents with `launchctl list` and remove any unrecognised or unnecessary persistence items.",
        "Deploy application allow-listing via PPPC profiles through your MDM solution.",
        "Run Rootstock periodically (e.g., monthly or after major software installs) to detect new attack paths introduced by vendor updates.",
    ],
}


# ── Themed Section Builders ──────────────────────────────────────────────────

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


# ── Report Assembly ───────────────────────────────────────────────────────────

def assemble_report(
    query_results: dict[str, list[dict] | str],
    metadata: dict,
) -> str:
    """Assemble the full Markdown report from query results and metadata."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    queries = discover_queries()

    def get_rows(filename: str) -> list[dict]:
        result = query_results.get(filename, [])
        return result if isinstance(result, list) else []

    injectable_rows = get_rows("01-injectable-fda-apps.cypher")
    path_rows = get_rows("02-shortest-path-to-fda.cypher")
    electron_rows = get_rows("03-electron-tcc-inheritance.cypher")
    private_ent_rows = get_rows("04-private-entitlement-audit.cypher")
    apple_event_rows = get_rows("05-appleevent-tcc-cascade.cypher")
    tcc_overview_rows = get_rows("07-tcc-grant-overview.cypher")

    # New data sources for extended executive summary
    tier_rows = get_rows("46-tier-classification.cypher")
    icloud_rows_68 = get_rows("68-injectable-icloud-sync.cypher")
    icloud_rows_69 = get_rows("69-cloudkit-container-injection.cypher")
    icloud_rows_70 = get_rows("70-icloud-keychain-sync-exposure.cypher")
    cert_rows_60 = get_rows("60-expired-cert-with-tcc.cypher")
    cert_rows_61 = get_rows("61-adhoc-signed-with-tcc.cypher")
    cert_rows_62 = get_rows("62-non-apple-ca-chain.cypher")

    critical_count = len(injectable_rows) + len(path_rows)
    high_count = len(electron_rows) + len(apple_event_rows)

    # Tier counts from query 46 — map integer tier values to "Tier N" labels
    tier_counts: dict[str, int] = {}
    for row in tier_rows:
        raw_tier = row.get("tier")
        if raw_tier is not None:
            tier_label = f"Tier {raw_tier}"
        else:
            tier_label = "Unclassified"
        tier_counts[tier_label] = tier_counts.get(tier_label, 0) + 1

    icloud_exposure_count = len(icloud_rows_68) + len(icloud_rows_69) + len(icloud_rows_70)
    certificate_risk_count = len(cert_rows_60) + len(cert_rows_61) + len(cert_rows_62)

    # Build top 3 attack path descriptions for the executive summary
    top_paths: list[str] = []
    for row in injectable_rows[:2]:
        app = row.get("app_name", "?")
        methods = list_or_str(row.get("injection_methods", []))
        top_paths.append(
            f"{app} has Full Disk Access and is injectable via `{methods}`."
        )
    for row in electron_rows[:1]:
        app = row.get("app_name", "?")
        perms = list_or_str(row.get("inherited_permissions", []))
        top_paths.append(
            f"{app} (Electron) inherits TCC permissions ({perms}) via ELECTRON_RUN_AS_NODE abuse."
        )

    sections: list[str] = []

    # ── Header ────────────────────────────────────────────────────────────────
    sections.append("# Rootstock Security Assessment Report")
    sections.append(f"_Generated: {now}_")
    sections.append("")

    # ── Scan Metadata ─────────────────────────────────────────────────────────
    sections.append("## Scan Metadata")
    meta_table = [
        ["Hostname", metadata.get("hostname") or socket.gethostname()],
        ["macOS Version", metadata.get("macos_version") or "unknown"],
        ["Scan Timestamp", metadata.get("timestamp") or now],
        ["Scan ID", metadata.get("scan_id") or "unknown"],
        ["Collector Version", metadata.get("collector_version") or "unknown"],
        ["Elevation", "root" if metadata.get("is_root") else "user"],
        ["Full Disk Access (collector)", "Yes" if metadata.get("has_fda") else "No"],
        ["Total Apps Scanned", str(metadata["app_count"]) if "app_count" in metadata else "unknown"],
        ["TCC Grants Found", str(metadata["tcc_grant_count"]) if "tcc_grant_count" in metadata else "unknown"],
        ["Entitlements Extracted", str(metadata["entitlement_count"]) if "entitlement_count" in metadata else "unknown"],
        ["Bluetooth Devices", str(metadata["bluetooth_device_count"]) if "bluetooth_device_count" in metadata else "—"],
        ["File ACLs Audited", str(metadata["file_acl_count"]) if "file_acl_count" in metadata else "—"],
        ["Login Sessions", str(metadata["login_session_count"]) if "login_session_count" in metadata else "—"],
    ]

    # iCloud posture
    icloud_signed = metadata.get("icloud_signed_in")
    if icloud_signed is not None:
        meta_table.append(["iCloud Signed In", "Yes" if icloud_signed else "No"])
        meta_table.append(["iCloud Drive", "Yes" if metadata.get("icloud_drive_enabled") else "No"])
        meta_table.append(["iCloud Keychain", "Yes" if metadata.get("icloud_keychain_enabled") else "No"])

    sections.append(tabulate(meta_table, tablefmt="github"))
    sections.append("")

    # ── Executive Summary ─────────────────────────────────────────────────────
    sections.append("## Executive Summary")
    sections.append(format_executive_summary(
        critical_count,
        high_count,
        top_paths,
        tier_counts=tier_counts or None,
        icloud_exposure_count=icloud_exposure_count,
        certificate_risk_count=certificate_risk_count,
    ))
    sections.append("")

    # ── Vulnerability Intelligence subsection ────────────────────────────────
    try:
        from cve_enrichment import enrich_registry
        enriched = enrich_registry()
        if enriched:
            kev_cves = [e for e in enriched.values() if e.in_kev]
            high_epss = [e for e in enriched.values() if e.epss_score is not None and e.epss_score > 0.3]
            highest_epss = max(
                (e for e in enriched.values() if e.epss_score is not None),
                key=lambda e: e.epss_score,
                default=None,
            )

            if kev_cves or high_epss:
                vuln_lines = ["### Vulnerability Intelligence"]
                if kev_cves:
                    vuln_lines.append(f"- **CISA KEV CVEs:** {len(kev_cves)} actively exploited vulnerabilities")
                if high_epss:
                    vuln_lines.append(f"- **High exploitation probability:** {len(high_epss)} CVE(s) with EPSS > 0.3")
                if highest_epss and highest_epss.epss_score is not None:
                    vuln_lines.append(
                        f"- **Highest exploitation probability:** {highest_epss.base.cve_id} "
                        f"(EPSS {highest_epss.epss_score:.2f})"
                    )
                vuln_lines.append("")
                sections.extend(vuln_lines)
    except Exception:
        pass  # Enrichment not available — skip gracefully

    # ── Critical: Injectable FDA Apps ─────────────────────────────────────────
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
        # Synthesise path rows from injectable results when query 02 returned nothing
        synthetic = [
            {
                "node_names": ["attacker_payload", r.get("app_name", "?"), "Full Disk Access"],
                "rel_types": ["CAN_INJECT_INTO", "HAS_TCC_GRANT"],
                "path_length": 2,
            }
            for r in injectable_rows[:3]
        ]
        sections.append(mermaid_attack_paths_block(synthetic, max_paths=3))
    sections.append("")

    # ── High: Electron TCC Inheritance ────────────────────────────────────────
    sections.append("## High Findings: Electron TCC Inheritance")
    sections.append(
        "> **Risk:** Electron apps can be abused via the `ELECTRON_RUN_AS_NODE` environment "
        "variable to spawn a Node.js interpreter that inherits the parent process's TCC "
        "permissions. An attacker with local code execution can exploit this silently."
    )
    sections.append("")
    sections.append(format_electron_table(electron_rows))
    sections.append("")

    # ── High: Apple Event TCC Cascade ─────────────────────────────────────────
    sections.append("## High Findings: Apple Event TCC Cascade")
    sections.append(
        "> **Risk:** An app with Apple Event automation permission over a privileged app "
        "can invoke that app's capabilities transitively, gaining effective access to the "
        "target's TCC grants without holding those grants directly."
    )
    sections.append("")
    sections.append(format_apple_event_table(apple_event_rows))
    sections.append("")

    # ── Informational: TCC Grant Overview ─────────────────────────────────────
    sections.append("## Informational: TCC Grant Overview")
    sections.append(format_tcc_overview_table(tcc_overview_rows))
    sections.append("")

    if tcc_overview_rows:
        sections.append("### TCC Permission Distribution")
        sections.append(mermaid_tcc_pie(tcc_overview_rows))
        sections.append("")

    # ── Informational: Private Entitlement Audit ──────────────────────────────
    sections.append("## Informational: Private Entitlement Audit")
    sections.append(
        "> Private Apple entitlements (`com.apple.private.*`) grant capabilities not "
        "available to App Store apps. Third-party apps holding these are high-value "
        "targets: compromising them may yield elevated privileges."
    )
    sections.append("")
    sections.append(format_private_entitlement_table(private_ent_rows))
    sections.append("")

    # ── NEW Section 1: Advanced Attack Paths ──────────────────────────────────
    sections.append("## Advanced Attack Paths: Injection Chains & XPC Escalation")
    sections.append(
        "> **Risk:** Multi-hop injection chains, XPC services without client verification, "
        "and sandbox escape paths allow attackers to escalate privileges beyond direct "
        "TCC injection. These paths often bypass single-layer defences."
    )
    sections.append("")
    sections.append(_section_for_queries(query_results, ["11", "13", "15", "30"], queries))
    sections.append("")

    # ── NEW Section 2: Code Signing & Certificate Risk ────────────────────────
    sections.append("## Code Signing & Certificate Risk")
    sections.append(
        "> **Risk:** Apps signed with expired certificates, ad-hoc signatures, or "
        "non-Apple CA chains have weaker trust guarantees. If these apps hold TCC "
        "grants, an attacker can more easily forge or replace them."
    )
    sections.append("")
    sections.append(_section_for_queries(query_results, ["37", "60", "61", "62"], queries))
    sections.append("")

    # ── NEW Section 3: Persistence & Hijack Risk ──────────────────────────────
    sections.append("## Persistence & Hijack Risk")
    sections.append(
        "> **Risk:** Hijackable LaunchDaemons, writable shell hooks, and unconstrained "
        "injectable services provide persistent footholds. An attacker who compromises "
        "these can survive reboots and maintain access indefinitely."
    )
    sections.append("")
    sections.append(_section_for_queries(query_results, ["29", "50", "51"], queries))
    sections.append("")

    # ── NEW Section 4: Authorization & Privilege Escalation ───────────────────
    sections.append("## Authorization & Privilege Escalation")
    sections.append(
        "> **Risk:** Admin group membership, weak authorization rights, sudoers NOPASSWD "
        "rules, and group-based capability escalation can grant an attacker root or "
        "near-root privileges without exploiting any vulnerability."
    )
    sections.append("")
    sections.append(_section_for_queries(query_results, ["24", "33", "36", "58"], queries))
    sections.append("")

    # ── NEW Section 5: File System & ACL Risk ─────────────────────────────────
    sections.append("## File System & ACL Risk")
    sections.append(
        "> **Risk:** Writable security-critical files (TCC.db, sudoers, sshd_config, "
        "LaunchDaemon directories) enable direct privilege escalation. File ACLs that "
        "grant write access to non-root users are high-priority findings."
    )
    sections.append("")
    sections.append(_section_for_queries(query_results, ["48", "49"], queries))
    sections.append("")

    # ── NEW Section 6: Physical & Remote Access Posture ───────────────────────
    posture_rows_67 = get_rows("67-physical-security-overview.cypher")
    sections.append("## Physical & Remote Access Posture")
    sections.append(
        "> **Risk:** Weak physical security posture (disabled screen lock, Thunderbolt "
        "in no-security mode, Lockdown Mode off) combined with enabled remote access "
        "services expands the attack surface to local and network-adjacent attackers."
    )
    sections.append("")
    sections.append(_section_for_queries(query_results, ["25", "64", "67"], queries))
    if posture_rows_67:
        sections.append("### Physical Security Posture Diagram")
        sections.append(mermaid_posture_summary(posture_rows_67))
    sections.append("")

    # ── NEW Section 7: Cloud & iCloud Risk ────────────────────────────────────
    sections.append("## Cloud & iCloud Risk")
    sections.append(
        "> **Risk:** Injectable applications with iCloud container entitlements can "
        "exfiltrate data via iCloud sync to all devices enrolled in the same Apple ID. "
        "iCloud Keychain sync exposes credentials across the device fleet."
    )
    sections.append("")
    sections.append(_section_for_queries(query_results, ["68", "69", "70"], queries))
    if icloud_rows_68:
        sections.append("### iCloud Risk Flow Diagram")
        sections.append(mermaid_icloud_risk_flow(icloud_rows_68))
    sections.append("")

    # ── NEW Section 8: Tier Classification Overview ───────────────────────────
    sections.append("## Tier Classification Overview")
    sections.append(
        "> Tier 0 assets are the crown jewels — apps with Full Disk Access, "
        "Accessibility, or Screen Recording grants that are injectable. Tier 1 "
        "apps hold moderate TCC grants. Tier 2 is everything else."
    )
    sections.append("")
    sections.append(_section_for_queries(query_results, ["46", "57"], queries))
    if tier_counts:
        sections.append("### Tier Distribution")
        sections.append(mermaid_tier_pie(tier_counts))
    sections.append("")

    # ── Top Vulnerabilities & ATT&CK Mapping ─────────────────────────────
    # Read attack_categories from graph-native risk scoring (infer_risk_score.py).
    # Falls back to query-based detection if graph data is unavailable.
    active_categories: set[str] = set()
    risk_rows = get_rows("95-high-risk-apps.cypher")
    for row in risk_rows:
        cats = row.get("attack_categories")
        if isinstance(cats, list):
            active_categories.update(cats)

    # Fallback: if graph-native categories are empty, derive from query results
    if not active_categories:
        if injectable_rows:
            active_categories.update({"injectable_fda", "dyld_injection"})
        if electron_rows:
            active_categories.add("electron_inheritance")
        if apple_event_rows:
            active_categories.update({"apple_events", "tcc_bypass"})
        if get_rows("29-hijackable-launch-daemons.cypher"):
            active_categories.add("persistence_hijack")
        if get_rows("30-xpc-no-client-verification.cypher"):
            active_categories.add("xpc_exploitation")
        if get_rows("54-accessibility-abuse.cypher"):
            active_categories.add("accessibility_abuse")
        if get_rows("40-injectable-shared-keychain.cypher") or get_rows("59-keychain-crown-jewels.cypher"):
            active_categories.add("keychain_access")
        if get_rows("73-kerberos-ticket-theft.cypher"):
            active_categories.add("kerberos")
        if get_rows("64-weak-physical-posture.cypher"):
            active_categories.add("physical_security")
        if get_rows("24-admin-group-escalation.cypher") or get_rows("33-weak-authorization-rights.cypher") or get_rows("36-sudoers-nopasswd.cypher"):
            active_categories.add("authorization_hardening")
        if icloud_rows_68 or icloud_rows_69 or icloud_rows_70:
            active_categories.add("icloud_risk")
        if get_rows("50-shell-hook-injection.cypher"):
            active_categories.add("shell_hooks")
        if get_rows("48-file-acl-write-paths.cypher") or get_rows("49-file-permission-escalation.cypher"):
            active_categories.add("file_acl_escalation")
        if get_rows("55-injectable-esf-client.cypher") or get_rows("56-injectable-network-extension.cypher"):
            active_categories.add("esf_bypass")
        if get_rows("27-sandbox-escape-risk.cypher"):
            active_categories.add("sandbox_escape")
        if get_rows("10-mdm-managed-tcc.cypher") or get_rows("39-mdm-overgrant.cypher"):
            active_categories.add("mdm_risk")
        if get_rows("25-remote-access-surface.cypher") or get_rows("52-cross-host-user.cypher") or get_rows("53-cross-host-injection-chain.cypher"):
            active_categories.add("lateral_movement")
        if get_rows("38-running-injectable-with-tcc.cypher"):
            active_categories.add("running_processes")
        if cert_rows_60 or cert_rows_61 or cert_rows_62:
            active_categories.add("certificate_hygiene")
        if get_rows("34-non-apple-auth-plugins.cypher"):
            active_categories.add("auth_plugin_risk")
        if get_rows("28-firewall-exposed-injectable.cypher"):
            active_categories.add("firewall_exposure")
        if get_rows("88-unquarantined-apps.cypher") or get_rows("89-quarantine-bypass-with-tcc.cypher"):
            active_categories.add("gatekeeper_bypass")

    vuln_section = _build_vulnerability_section(active_categories)
    if vuln_section:
        sections.append("## Top Vulnerabilities & ATT&CK Mapping")
        sections.append(
            "> CVE references and MITRE ATT&CK techniques relevant to findings on this host."
        )
        sections.append("")
        sections.append(vuln_section)
        sections.append("")

    # ── Threat Landscape: APT Group Exposure ─────────────────────────────
    threat_rows = get_rows("92-apt-group-exposure.cypher")
    if threat_rows:
        sections.append("## Threat Landscape: APT Group Exposure")
        sections.append(
            "> APT groups whose techniques are relevant to vulnerabilities found on this host."
        )
        sections.append("")
        sections.append(format_generic_table(threat_rows))
        sections.append("")

    # ── Recommendations ───────────────────────────────────────────────────────
    sections.append("## Recommendations")

    _append_recommendations(sections, "Injectable Applications with Privileged TCC Grants",
                            "injectable_fda", bool(injectable_rows))
    _append_recommendations(sections, "Electron Application Hardening",
                            "electron_inheritance", bool(electron_rows))
    _append_recommendations(sections, "Apple Event Automation Hygiene",
                            "apple_events", bool(apple_event_rows))
    _append_recommendations(sections, "Physical Security Hardening",
                            "physical_security", bool(posture_rows_67))
    _append_recommendations(sections, "Certificate Hygiene",
                            "certificate_hygiene", bool(cert_rows_60 or cert_rows_61 or cert_rows_62))
    _append_recommendations(sections, "iCloud Risk Mitigation",
                            "icloud_risk", bool(icloud_rows_68 or icloud_rows_69 or icloud_rows_70))
    _append_recommendations(sections, "Authorization Hardening",
                            "authorization_hardening",
                            bool(get_rows("24-admin-group-escalation.cypher")
                                 or get_rows("33-weak-authorization-rights.cypher")
                                 or get_rows("36-sudoers-nopasswd.cypher")
                                 or get_rows("58-group-capability-escalation.cypher")))
    _append_recommendations(sections, "Shell Hook Hardening",
                            "shell_hooks", bool(get_rows("50-shell-hook-injection.cypher")))
    _append_recommendations(sections, "File ACL Escalation Mitigation",
                            "file_acl_escalation",
                            bool(get_rows("48-file-acl-write-paths.cypher")
                                 or get_rows("49-file-permission-escalation.cypher")))
    _append_recommendations(sections, "Endpoint Security Framework Protection",
                            "esf_bypass",
                            bool(get_rows("55-injectable-esf-client.cypher")
                                 or get_rows("56-injectable-network-extension.cypher")))
    _append_recommendations(sections, "Sandbox Escape Mitigation",
                            "sandbox_escape", bool(get_rows("27-sandbox-escape-risk.cypher")))
    _append_recommendations(sections, "MDM Configuration Hygiene",
                            "mdm_risk",
                            bool(get_rows("10-mdm-managed-tcc.cypher")
                                 or get_rows("39-mdm-overgrant.cypher")))
    _append_recommendations(sections, "Lateral Movement Mitigation",
                            "lateral_movement",
                            bool(get_rows("25-remote-access-surface.cypher")
                                 or get_rows("52-cross-host-user.cypher")
                                 or get_rows("53-cross-host-injection-chain.cypher")))
    _append_recommendations(sections, "Running Process Hardening",
                            "running_processes",
                            bool(get_rows("38-running-injectable-with-tcc.cypher")))
    _append_recommendations(sections, "Gatekeeper Bypass Mitigation",
                            "gatekeeper_bypass",
                            bool(get_rows("88-unquarantined-apps.cypher")
                                 or get_rows("89-quarantine-bypass-with-tcc.cypher")))

    sections.append("### General macOS Hardening")
    for rec in RECOMMENDATIONS["general"]:
        sections.append(f"- {rec}")
    sections.append("")

    # ── Appendix: Raw Query Results ───────────────────────────────────────────
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

    return "\n".join(sections)


# ── HTML Conversion ───────────────────────────────────────────────────────────

def markdown_to_html(md: str) -> str:
    """Convert Markdown report to HTML. Uses `markdown` package if available."""
    try:
        import markdown as md_lib
        body = md_lib.markdown(md, extensions=["tables", "fenced_code"])
    except ImportError:
        # Minimal fallback — preserves readability without the markdown package
        lines = []
        in_list = False
        for line in md.split("\n"):
            if line.startswith("# "):
                if in_list:
                    lines.append("</ul>")
                    in_list = False
                lines.append(f"<h1>{html_mod.escape(line[2:])}</h1>")
            elif line.startswith("## "):
                if in_list:
                    lines.append("</ul>")
                    in_list = False
                lines.append(f"<h2>{html_mod.escape(line[3:])}</h2>")
            elif line.startswith("### "):
                if in_list:
                    lines.append("</ul>")
                    in_list = False
                lines.append(f"<h3>{html_mod.escape(line[4:])}</h3>")
            elif line.startswith("- "):
                if not in_list:
                    lines.append("<ul>")
                    in_list = True
                lines.append(f"<li>{html_mod.escape(line[2:])}</li>")
            elif line.strip():
                if in_list:
                    lines.append("</ul>")
                    in_list = False
                lines.append(f"<p>{html_mod.escape(line)}</p>")
        if in_list:
            lines.append("</ul>")
        body = "\n".join(lines)

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Rootstock Security Assessment Report</title>
  <style>
    :root {{
      --bg-primary: #0d1117;
      --bg-secondary: #161b22;
      --bg-tertiary: #1c2333;
      --border: #30363d;
      --text-primary: #e6edf3;
      --text-secondary: #8b949e;
      --text-muted: #484f58;
      --accent-blue: #58a6ff;
      --accent-red: #f85149;
      --accent-orange: #d29922;
      --accent-green: #3fb950;
      --accent-purple: #bc8cff;
      --severity-critical: #f85149;
      --severity-high: #d29922;
      --severity-medium: #58a6ff;
      --severity-low: #3fb950;
    }}
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", sans-serif;
      max-width: 1200px; margin: 0 auto; padding: 40px 24px;
      background: var(--bg-primary); color: var(--text-primary);
      line-height: 1.6;
    }}
    a {{ color: var(--accent-blue); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}

    /* Header */
    h1 {{
      color: var(--text-primary);
      font-size: 1.8em;
      font-weight: 700;
      padding-bottom: 12px;
      margin-bottom: 8px;
      border-bottom: 3px solid var(--accent-red);
      display: flex;
      align-items: center;
      gap: 12px;
    }}
    h1::before {{
      content: "R";
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 36px; height: 36px;
      background: linear-gradient(135deg, #e63946, #d62828);
      border-radius: 8px;
      font-size: 20px;
      font-weight: 700;
      color: #fff;
      flex-shrink: 0;
      box-shadow: 0 2px 8px rgba(230,57,70,.3);
    }}
    h2 {{
      color: var(--text-primary);
      font-size: 1.3em;
      font-weight: 600;
      padding: 10px 0 8px 0;
      margin-top: 2.5em;
      margin-bottom: 0.8em;
      border-bottom: 1px solid var(--border);
      position: relative;
    }}
    /* Severity-coded section borders */
    h2:has(+ blockquote) {{
      padding-left: 14px;
    }}
    h3 {{
      color: var(--accent-blue);
      font-size: 1.05em;
      font-weight: 600;
      margin-top: 1.8em;
      margin-bottom: 0.6em;
    }}
    h4 {{
      color: var(--text-secondary);
      font-size: 0.95em;
      font-weight: 600;
      margin-top: 1.2em;
      margin-bottom: 0.5em;
    }}
    p {{ margin: 0.8em 0; color: var(--text-primary); }}
    em {{ color: var(--text-secondary); }}

    /* Tables */
    table {{
      border-collapse: collapse;
      width: 100%;
      margin: 1em 0;
      font-size: 0.88em;
      border-radius: 8px;
      overflow: hidden;
      border: 1px solid var(--border);
    }}
    th, td {{
      padding: 10px 14px;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }}
    th {{
      background: var(--bg-tertiary);
      color: var(--text-secondary);
      font-weight: 600;
      font-size: 0.85em;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    tr:nth-child(even) {{ background: rgba(22,27,34,.5); }}
    tr:hover {{ background: rgba(88,166,255,.06); }}
    td {{ color: var(--text-primary); }}

    /* Blockquotes (risk callouts) */
    blockquote {{
      background: var(--bg-secondary);
      border-left: 4px solid var(--accent-orange);
      padding: 14px 18px;
      margin: 1.2em 0;
      border-radius: 0 8px 8px 0;
      color: var(--text-secondary);
      font-size: 0.92em;
      backdrop-filter: blur(4px);
    }}
    blockquote strong {{ color: var(--accent-orange); }}

    /* Code */
    code {{
      background: var(--bg-secondary);
      border: 1px solid var(--border);
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 0.88em;
      font-family: "SF Mono", Menlo, "Fira Code", monospace;
      color: var(--accent-blue);
    }}
    pre {{
      background: var(--bg-secondary);
      border: 1px solid var(--border);
      padding: 16px;
      border-radius: 8px;
      overflow-x: auto;
      font-size: 0.88em;
    }}
    pre code {{
      border: none;
      padding: 0;
      background: transparent;
    }}

    /* Lists */
    ul, ol {{ padding-left: 24px; margin: 0.8em 0; }}
    li {{
      margin: 0.4em 0;
      color: var(--text-primary);
      line-height: 1.5;
    }}
    li::marker {{ color: var(--text-muted); }}

    /* Severity badges via text patterns */
    strong {{ color: var(--text-primary); }}

    /* Tier badges */
    .tier-0 {{ color: var(--severity-critical); font-weight: 700; }}
    .tier-1 {{ color: var(--severity-high); font-weight: 700; }}
    .tier-2 {{ color: var(--severity-medium); font-weight: 600; }}

    /* Mermaid diagrams */
    .mermaid {{ margin: 1.5em 0; }}

    /* Print styles */
    @media print {{
      body {{ background: #fff; color: #111; max-width: 100%; padding: 20px; }}
      h1 {{ color: #c62828; }}
      h1::before {{ background: #c62828; }}
      h2 {{ color: #333; border-bottom-color: #ddd; }}
      h3 {{ color: #2255aa; }}
      table {{ border-color: #ddd; }}
      th {{ background: #f4f4f4; color: #333; }}
      tr:nth-child(even) {{ background: #fafafa; }}
      blockquote {{ background: #fff8e1; border-left-color: #ffc107; color: #555; }}
      code {{ background: #f4f4f4; color: #c62828; border-color: #ddd; }}
      pre {{ background: #f4f4f4; border-color: #ddd; }}
    }}

    /* Footer */
    .report-footer {{
      margin-top: 3em;
      padding-top: 1.5em;
      border-top: 1px solid var(--border);
      font-size: 0.85em;
      color: var(--text-muted);
      text-align: center;
    }}
  </style>
</head>
<body>
{body}
<div class="report-footer">
  Generated by Rootstock &mdash; macOS Attack Path Discovery
</div>
</body>
</html>"""
