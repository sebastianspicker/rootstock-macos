"""
infer_host_posture.py - Score the scanned host's own security settings.

Runs in the score stage next to application risk scoring. Sets per Computer:
  - posture_findings (list[str]): settings that definitely weaken the machine
  - posture_unknown (list[str]): settings the collector could not read
  - risk_score / risk_level derived from the findings (never from unknowns)

Unknown and weak are kept apart on purpose: a sandboxed or unprivileged scan
that could not read FileVault state must not report "FileVault is off".

Besides the core protections (SIP, Gatekeeper, FileVault, screen lock, firewall)
the assessment weighs account settings (guest, automatic login, root), remote
control services (Remote Apple Events, Remote Management), Software Update
settings, custom root certificates trusted in the user or admin domain, network
listeners reachable while the firewall is off, proxy and hosts-file overrides, and
macOS CVEs matched against the installed build when the vulnerability import set
``macos_cve_count`` / ``macos_kev_cve_count`` on the Computer node.
"""

from __future__ import annotations

from dataclasses import dataclass

from neo4j import Session

from ..constants import RISK_LEVEL_PROPERTY, RISK_SCORE_PROPERTY


def risk_level(score: float) -> str:
    if score <= 0:
        return "informational"
    if score >= 7.5:
        return "critical"
    if score >= 5.5:
        return "high"
    if score >= 3.0:
        return "medium"
    return "low"


@dataclass(frozen=True)
class HostFacts:
    computer_key: str
    sip_enabled: bool | None = None
    gatekeeper_enabled: bool | None = None
    filevault_enabled: bool | None = None
    firewall_enabled: bool | None = None
    screen_lock_enabled: bool | None = None
    screen_lock_delay: int | None = None
    ssh_enabled: bool | None = None
    screen_sharing_enabled: bool | None = None
    nopasswd_rules: int = 0
    writable_privileged_files: int = 0
    secure_boot_level: str | None = None
    external_boot_allowed: bool | None = None
    bluetooth_discoverable: bool | None = None
    unresolved_tcc_grants: int = 0
    guest_account_enabled: bool | None = None
    auto_login_user: str | None = None
    root_account_enabled: bool | None = None
    remote_apple_events_enabled: bool | None = None
    remote_management_enabled: bool | None = None
    install_security_responses: bool | None = None
    install_system_updates: bool | None = None
    automatic_check: bool | None = None
    custom_root_cas: int = 0
    custom_root_subjects: tuple[str, ...] = ()
    unfiltered_exposed_listeners: int = 0
    proxy_count: int | None = None
    hosts_entry_count: int | None = None
    xprotect_version: str | None = None
    macos_cve_count: int | None = None
    macos_kev_cve_count: int | None = None


@dataclass(frozen=True)
class PostureAssessment:
    score: float
    level: str
    findings: list[str]
    unknown: list[str]


_POSTURE_CHECKS: tuple[tuple[str, str, float, str], ...] = (
    # (attribute, unknown label, weight, finding text)
    ("sip_enabled", "System Integrity Protection", 4.0, "System Integrity Protection is disabled"),
    ("gatekeeper_enabled", "Gatekeeper", 3.0, "Gatekeeper assessments are disabled"),
    ("filevault_enabled", "FileVault", 3.0, "FileVault disk encryption is off"),
    (
        "screen_lock_enabled",
        "screen lock",
        2.5,
        "The screen does not require a password after sleep or screen saver",
    ),
    ("firewall_enabled", "application firewall", 1.5, "The application firewall is off"),
)


def _posture_extra_findings(facts: HostFacts) -> list[tuple[float, str]]:
    """Weighted findings beyond the tri-state checks; each entry applies when its test holds."""
    slow_lock = (
        facts.screen_lock_enabled is True
        and facts.screen_lock_delay is not None
        and facts.screen_lock_delay > 5
    )
    reduced_boot = bool(facts.secure_boot_level) and facts.secure_boot_level != "full"
    candidates: list[tuple[bool, float, str]] = [
        (
            slow_lock,
            1.0,
            f"Screen lock waits {facts.screen_lock_delay} seconds before requiring a password",
        ),
        (facts.ssh_enabled is True, 1.5, "Remote Login (SSH) is enabled"),
        (facts.screen_sharing_enabled is True, 1.5, "Screen Sharing is enabled"),
        (
            facts.nopasswd_rules > 0,
            2.0,
            f"{facts.nopasswd_rules} sudoers rule(s) allow sudo without a password",
        ),
        (
            facts.writable_privileged_files > 0,
            3.0,
            f"{facts.writable_privileged_files} privileged file(s) are writable by non-root users",
        ),
        (reduced_boot, 1.5, f"Secure Boot is set to {facts.secure_boot_level} security"),
        (facts.external_boot_allowed is True, 1.0, "Booting from external media is allowed"),
        (facts.bluetooth_discoverable is True, 0.5, "Bluetooth is discoverable"),
    ]
    candidates.extend(_settings_findings(facts))
    return [(weight, text) for applies, weight, text in candidates if applies]


def _settings_findings(facts: HostFacts) -> list[tuple[bool, float, str]]:
    """Accounts, remote control, updates, trust and network overrides (definite values only)."""
    subjects = ", ".join(facts.custom_root_subjects[:3])
    more = facts.custom_root_cas - min(3, len(facts.custom_root_subjects))
    if subjects and more > 0:
        subjects += f" and {more} more"
    named_roots = f": {subjects}" if subjects else ""
    return [
        (facts.guest_account_enabled is True, 1.5, "The guest account is enabled"),
        (
            bool(facts.auto_login_user),
            2.5,
            f"Automatic login is enabled for {facts.auto_login_user}",
        ),
        (facts.root_account_enabled is True, 2.5, "The root account is enabled"),
        (facts.remote_apple_events_enabled is True, 1.0, "Remote Apple Events are enabled"),
        (
            facts.remote_management_enabled is True,
            1.5,
            "Remote Management (Apple Remote Desktop) is enabled",
        ),
        (
            facts.install_security_responses is False,
            2.0,
            "Security responses and system data files are not installed automatically",
        ),
        (
            facts.install_system_updates is False,
            1.0,
            "macOS updates are not installed automatically",
        ),
        (facts.automatic_check is False, 1.5, "Software Update does not check for updates"),
        (
            facts.custom_root_cas > 0,
            2.0,
            f"{facts.custom_root_cas} custom root certificate(s) are trusted{named_roots}",
        ),
        (
            facts.unfiltered_exposed_listeners > 0,
            1.5,
            f"{facts.unfiltered_exposed_listeners} network listener(s) accept connections from "
            "other machines while the firewall is off",
        ),
        (
            bool(facts.proxy_count),
            0.5,
            f"{facts.proxy_count} proxy setting(s) route web traffic through another host "
            "(expected on managed networks; confirm they are yours)",
        ),
        (
            bool(facts.hosts_entry_count),
            0.5,
            f"/etc/hosts overrides name resolution for {facts.hosts_entry_count} address(es)",
        ),
        *_macos_cve_findings(facts),
    ]


def _macos_cve_findings(facts: HostFacts) -> list[tuple[bool, float, str]]:
    if facts.macos_kev_cve_count:
        return [
            (
                True,
                3.0,
                f"The installed macOS build is affected by {facts.macos_kev_cve_count} "
                "actively exploited CVE(s) (CISA KEV)",
            )
        ]
    if facts.macos_cve_count:
        return [
            (
                True,
                1.0,
                f"The installed macOS build is affected by {facts.macos_cve_count} known CVE(s)",
            )
        ]
    return []


def _posture_unknowns(facts: HostFacts) -> list[str]:
    unknown = [
        label for attribute, label, _w, _t in _POSTURE_CHECKS if getattr(facts, attribute) is None
    ]
    if facts.ssh_enabled is None:
        unknown.append("Remote Login")
    if not facts.xprotect_version:
        unknown.append("XProtect version")
    if facts.unresolved_tcc_grants:
        unknown.append(
            f"{facts.unresolved_tcc_grants} privacy grant(s) for clients that are not installed apps"
        )
    return unknown


def assess_host(facts: HostFacts) -> PostureAssessment:
    """Pure posture scoring: definite weaknesses count, unknown settings are listed apart."""
    weighted = [
        (weight, text)
        for attribute, _label, weight, text in _POSTURE_CHECKS
        if getattr(facts, attribute) is False
    ]
    weighted.extend(_posture_extra_findings(facts))
    score = round(min(10.0, sum(weight for weight, _ in weighted)), 2)
    return PostureAssessment(
        score=score,
        level=risk_level(score),
        findings=[text for _, text in weighted],
        unknown=_posture_unknowns(facts),
    )


# ── Graph I/O ────────────────────────────────────────────────────────────────


_HOST_FACTS_QUERY = """
    MATCH (c:Computer)
    OPTIONAL MATCH (f:FirewallPolicy)
    WITH c, collect(f.enabled)[0] AS firewall_enabled
    OPTIONAL MATCH (ssh:RemoteAccessService {service: 'ssh'})
    OPTIONAL MATCH (vnc:RemoteAccessService {service: 'screen_sharing'})
    WITH c, firewall_enabled, collect(ssh.enabled)[0] AS ssh_enabled,
         collect(vnc.enabled)[0] AS screen_sharing_enabled
    OPTIONAL MATCH (sr:SudoersRule {nopasswd: true})
    WITH c, firewall_enabled, ssh_enabled, screen_sharing_enabled, count(DISTINCT sr) AS nopasswd_rules
    OPTIONAL MATCH (cf:CriticalFile)
    WHERE cf.category IN ['tcc_database', 'sudoers', 'launch_daemon_dir', 'authorization_db', 'ssh_config']
      AND cf.is_writable_by_non_root = true
    WITH c, firewall_enabled, ssh_enabled, screen_sharing_enabled, nopasswd_rules,
         count(DISTINCT cf) AS writable_privileged_files
    OPTIONAL MATCH (u:UnresolvedTCCGrant {scan_id: c.scan_id})
    WITH c, firewall_enabled, ssh_enabled, screen_sharing_enabled, nopasswd_rules,
         writable_privileged_files, count(DISTINCT u) AS unresolved_tcc_grants
    OPTIONAL MATCH (tc:TrustedCertificate {scan_id: c.scan_id, custom_root: true})
    WITH c, firewall_enabled, ssh_enabled, screen_sharing_enabled, nopasswd_rules,
         writable_privileged_files, unresolved_tcc_grants,
         count(DISTINCT tc) AS custom_root_cas, collect(DISTINCT tc.subject) AS custom_root_subjects
    RETURN c.computer_key AS computer_key,
           c.sip_enabled AS sip_enabled,
           c.gatekeeper_enabled AS gatekeeper_enabled,
           c.filevault_enabled AS filevault_enabled,
           firewall_enabled,
           c.screen_lock_enabled AS screen_lock_enabled,
           c.screen_lock_delay AS screen_lock_delay,
           ssh_enabled,
           screen_sharing_enabled,
           nopasswd_rules,
           writable_privileged_files,
           c.secure_boot_level AS secure_boot_level,
           c.external_boot_allowed AS external_boot_allowed,
           c.bluetooth_discoverable AS bluetooth_discoverable,
           unresolved_tcc_grants,
           c.guest_account_enabled AS guest_account_enabled,
           c.auto_login_user AS auto_login_user,
           c.root_account_enabled AS root_account_enabled,
           c.remote_apple_events_enabled AS remote_apple_events_enabled,
           c.remote_management_enabled AS remote_management_enabled,
           c.software_update_install_security_responses AS install_security_responses,
           c.software_update_install_system_updates AS install_system_updates,
           c.software_update_automatic_check AS automatic_check,
           custom_root_cas,
           custom_root_subjects,
           COUNT {
               MATCH (nl:NetworkListener {scan_id: c.scan_id})
               WHERE nl.reachable_without_firewall = true
           } AS unfiltered_exposed_listeners,
           c.proxy_count AS proxy_count,
           c.hosts_entry_count AS hosts_entry_count,
           c.xprotect_version AS xprotect_version,
           c.macos_cve_count AS macos_cve_count,
           c.macos_kev_cve_count AS macos_kev_cve_count
"""


def _host_facts_from_record(record) -> HostFacts:
    return HostFacts(
        computer_key=record["computer_key"],
        sip_enabled=record["sip_enabled"],
        gatekeeper_enabled=record["gatekeeper_enabled"],
        filevault_enabled=record["filevault_enabled"],
        firewall_enabled=record["firewall_enabled"],
        screen_lock_enabled=record["screen_lock_enabled"],
        screen_lock_delay=record["screen_lock_delay"],
        ssh_enabled=record["ssh_enabled"],
        screen_sharing_enabled=record["screen_sharing_enabled"],
        nopasswd_rules=int(record["nopasswd_rules"] or 0),
        writable_privileged_files=int(record["writable_privileged_files"] or 0),
        secure_boot_level=record["secure_boot_level"],
        external_boot_allowed=record["external_boot_allowed"],
        bluetooth_discoverable=record["bluetooth_discoverable"],
        unresolved_tcc_grants=int(record["unresolved_tcc_grants"] or 0),
        **_settings_facts_from_record(record),
    )


def _settings_facts_from_record(record) -> dict[str, object]:
    return {
        "guest_account_enabled": record["guest_account_enabled"],
        "auto_login_user": record["auto_login_user"],
        "root_account_enabled": record["root_account_enabled"],
        "remote_apple_events_enabled": record["remote_apple_events_enabled"],
        "remote_management_enabled": record["remote_management_enabled"],
        "install_security_responses": record["install_security_responses"],
        "install_system_updates": record["install_system_updates"],
        "automatic_check": record["automatic_check"],
        "custom_root_cas": int(record["custom_root_cas"] or 0),
        "custom_root_subjects": tuple(sorted(record["custom_root_subjects"] or ())),
        "unfiltered_exposed_listeners": int(record["unfiltered_exposed_listeners"] or 0),
        "proxy_count": record["proxy_count"],
        "hosts_entry_count": record["hosts_entry_count"],
        "xprotect_version": record["xprotect_version"],
        "macos_cve_count": record["macos_cve_count"],
        "macos_kev_cve_count": record["macos_kev_cve_count"],
    }


def infer(session: Session) -> int:
    """Assess every Computer node; returns the number of hosts scored."""
    rows = []
    for record in session.run(_HOST_FACTS_QUERY):
        facts = _host_facts_from_record(record)
        if not facts.computer_key:
            continue
        assessment = assess_host(facts)
        rows.append(
            {
                "computer_key": facts.computer_key,
                "score": assessment.score,
                "level": assessment.level,
                "findings": assessment.findings,
                "unknown": assessment.unknown,
            }
        )
    if not rows:
        return 0
    session.run(
        f"""
        UNWIND $rows AS row
        MATCH (c:Computer {{computer_key: row.computer_key}})
        SET c.{RISK_SCORE_PROPERTY} = row.score,
            c.{RISK_LEVEL_PROPERTY} = row.level,
            c.posture_findings = row.findings,
            c.posture_unknown = row.unknown
        """,
        rows=rows,
    )
    return len(rows)
