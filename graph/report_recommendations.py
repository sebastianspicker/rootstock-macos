"""Recommendation catalog and section assembly for Rootstock reports."""

from __future__ import annotations


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


def _append_recommendations_section(
    sections: list[str],
    query_results: dict[str, list[dict] | str],
    rows: object,
) -> None:
    sections.append("## Recommendations")
    state = {
        "injectable_rows": rows.injectable,
        "electron_rows": rows.electron,
        "apple_event_rows": rows.apple_event,
        "posture_rows_67": _get_query_rows(
            query_results, "67-physical-security-overview.cypher"
        ),
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
            bool(state["posture_rows_67"]),
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
