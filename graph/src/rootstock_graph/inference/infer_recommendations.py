"""
infer_recommendations.py - Create graph-native Recommendation nodes with edges.

Creates (:Recommendation) nodes and links them to the node they apply to:

  (:Application)-[:HAS_RECOMMENDATION]->(:Recommendation)   app-specific advice
  (:Computer)-[:HAS_RECOMMENDATION]->(:Recommendation)       host-setting advice

Every recommendation is written for the person who administers the scanned Mac:
it names the setting or action they can take (revoke a grant, update an app,
turn a service off) and says why. Developer-side fixes (enable Hardened Runtime)
are mentioned only as something to ask a vendor for.

Version-matched registry CVEs produce one recommendation per CVE (`patch_<cve_id>`)
whose text carries the patched version, so the advice is specific to what is installed.
NVD matches for installed software (match_tier 'cpe') produce one update recommendation
per app and one for macOS instead. Both live in infer_recommendations_cve.py.

Also creates (:Recommendation)-[:MITIGATES]->(:AttackTechnique) edges for
recommendations that map to ATT&CK techniques.
"""

from __future__ import annotations

import logging
from typing import Any, cast

from neo4j import Session
from neo4j.exceptions import Neo4jError

from ..category_predicates import RISK_CATEGORY_PREDICATES
from ..constants import ATTACKER_BUNDLE_ID
from .infer_recommendations_cve import (
    create_nvd_update_recommendations,
    create_patch_recommendations,
)
from .infer_recommendations_inventory import RULES as _INVENTORY_RULES
from .recommendation_rule import RecommendationRule

logger = logging.getLogger(__name__)


# ── Recommendation definitions ───────────────────────────────────────────────


_APP_RECOMMENDATION_TEMPLATE = """
    MATCH (app:Application)
    WHERE app.bundle_id <> $attacker_id AND ({condition})
    MATCH (r:Recommendation {{key: $key}})
    MERGE (app)-[:HAS_RECOMMENDATION]->(r)
    RETURN count(*) AS n
"""

_HOST_RECOMMENDATION_TEMPLATE = """
    MATCH (c:Computer)
    WHERE {condition}
    MATCH (r:Recommendation {{key: $key}})
    MERGE (c)-[:HAS_RECOMMENDATION]->(r)
    RETURN count(*) AS n
"""

_HAS_ANY_GRANT = "EXISTS { MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission) }"
_HAS_VALUE = (
    "("
    + _HAS_ANY_GRANT
    + " OR EXISTS { MATCH (app)-[:PERSISTS_VIA]->(:LaunchItem) }"
    + " OR EXISTS { MATCH (app)-[:CAN_READ_KEYCHAIN]->(:Keychain_Item) })"
)
_THIRD_PARTY = "NOT coalesce(app.is_system, false) AND NOT coalesce(app.is_sip_protected, false)"

_SETTINGS_PRIVACY = "System Settings › Privacy & Security"

_RECOMMENDATIONS: list[RecommendationRule] = [
    RecommendationRule(
        "revoke_unneeded_fda",
        "injectable_fda",
        "Review this app's Full Disk Access",
        f"This app holds Full Disk Access and code can be loaded into it, so anything running "
        f"as you could read every file through it. Remove it from {_SETTINGS_PRIVACY} › Full Disk "
        "Access unless it needs that access, and ask the vendor for a build with Hardened Runtime "
        "and Library Validation.",
        "critical",
        ("T1574.006",),
        RISK_CATEGORY_PREDICATES["injectable_fda"],
    ),
    RecommendationRule(
        "harden_runtime",
        "dyld_injection",
        "Hardened Runtime is off",
        "DYLD_INSERT_LIBRARIES can load any library into this app because it was built without "
        "Hardened Runtime. Update it to a current build or ask the vendor to enable Hardened "
        "Runtime; until then keep its privacy permissions and persistence to the minimum.",
        "high",
        ("T1574.006",),
        f"'dyld_insert' IN app.injection_methods AND {_HAS_VALUE}",
    ),
    RecommendationRule(
        "library_validation",
        "dyld_injection",
        "Library Validation is off",
        "The app accepts unsigned or differently-signed libraries. Update it or ask the vendor "
        "to enable Library Validation; meanwhile avoid granting it Full Disk Access, "
        "Accessibility or Screen Recording.",
        "high",
        ("T1574.006",),
        f"'missing_library_validation' IN app.injection_methods AND {_HAS_VALUE}",
    ),
    RecommendationRule(
        "disable_electron_node",
        "electron_inheritance",
        "Electron RunAsNode fuse is enabled",
        "Any local process can start this Electron app as a Node.js interpreter "
        "(ELECTRON_RUN_AS_NODE) and inherit its privacy permissions. Update the app; if the "
        "vendor cannot disable the fuse, do not grant it Full Disk Access, Accessibility or "
        "Screen Recording.",
        "high",
        ("T1574.006", "T1059.007"),
        RISK_CATEGORY_PREDICATES["electron_inheritance"],
    ),
    RecommendationRule(
        "review_automation_grants",
        "apple_events",
        "Review Automation permissions",
        f"This app may send Apple Events to apps that hold sensitive permissions. In "
        f"{_SETTINGS_PRIVACY} › Automation, remove its control over apps it does not need.",
        "medium",
        ("T1059.002",),
        RISK_CATEGORY_PREDICATES["apple_events"],
    ),
    RecommendationRule(
        "review_accessibility_grant",
        "accessibility_abuse",
        "Review this app's Accessibility permission",
        f"Accessibility lets the app read any window and synthesize input, and code can be "
        f"loaded into this app. Remove it from {_SETTINGS_PRIVACY} › Accessibility unless the "
        "feature is essential.",
        "high",
        ("T1056.002",),
        RISK_CATEGORY_PREDICATES["accessibility_abuse"],
    ),
    RecommendationRule(
        "replace_unsigned_app",
        "certificate_hygiene",
        "App is not code-signed",
        "macOS cannot tell who built this app or whether it was changed after download. "
        "Replace it with a signed build from the vendor, or remove it.",
        "high",
        ("T1553.001",),
        f"app.signed = false AND {_THIRD_PARTY}",
    ),
    RecommendationRule(
        "review_adhoc_signature",
        "certificate_hygiene",
        "App has an ad-hoc signature",
        "The signature carries no developer identity, so updates and integrity cannot be "
        "verified. Prefer a build signed with a Developer ID, especially if the app holds "
        "privacy permissions.",
        "medium",
        ("T1553.001",),
        f"coalesce(app.is_adhoc_signed, false) = true AND {_THIRD_PARTY}",
    ),
    RecommendationRule(
        "verify_unnotarized_app",
        "certificate_hygiene",
        "App is not notarized",
        "Gatekeeper reports no notarization ticket for this app, so Apple never scanned this "
        "build. Confirm you installed it from the vendor's official download, and update it "
        "if a notarized version exists.",
        "medium",
        ("T1553.001",),
        f"app.is_notarized = false AND {_THIRD_PARTY}",
    ),
    RecommendationRule(
        "verify_unquarantined_app",
        "gatekeeper_bypass",
        "App skipped Gatekeeper",
        "The app has no quarantine record and is not notarized, so it was never assessed on "
        "download (copied in by a tool, installer script or stripped attribute). Make sure you "
        "know where it came from before granting it any permission.",
        "medium",
        ("T1553.001",),
        "EXISTS { MATCH ()-[:BYPASSED_GATEKEEPER]->(app) }",
    ),
    RecommendationRule(
        "fix_persistence_permissions",
        "persistence_hijack",
        "Fix permissions on this app's launch item",
        "A LaunchDaemon or LaunchAgent belonging to this app has a plist or program that a "
        "non-root user can write. Whoever has that access can run their own code at every "
        "start, as root for daemons. Restore root ownership and 644 (plist) / 755 (program) "
        "permissions, or reinstall the app.",
        "critical",
        ("T1543.004", "T1547.011"),
        RISK_CATEGORY_PREDICATES["persistence_hijack"],
    ),
    RecommendationRule(
        "review_root_daemon",
        "persistence",
        "Injectable app installs a root daemon",
        "This app runs a LaunchDaemon as root and code can be loaded into the app. Update the "
        "app to a hardened build; if it is no longer needed, uninstall it so the daemon goes "
        "with it.",
        "high",
        ("T1543.004",),
        "size(app.injection_methods) > 0 AND EXISTS { MATCH (app)-[:PERSISTS_VIA]->(li:LaunchItem {type: 'daemon'}) "
        "OPTIONAL MATCH (li)-[:RUNS_AS]->(u:User) WITH li, u WHERE coalesce(u.name, 'root') = 'root' RETURN li }",
    ),
    RecommendationRule(
        "audit_keychain_trust",
        "keychain_access",
        "Review keychain items that trust this app",
        "Keychain items list this app as trusted, so it (and anything injected into it) can "
        "read them without a prompt. Open Keychain Access, check each item's Access Control "
        "tab, and remove the app where the access is not needed.",
        "high",
        ("T1555.001",),
        RISK_CATEGORY_PREDICATES["keychain_access"],
    ),
    RecommendationRule(
        "harden_esf_clients",
        "esf_bypass",
        "Security tool can be blinded",
        "This app is an Endpoint Security client and code can be loaded into it, so malware "
        "could disable your monitoring. Update the security product and report the missing "
        "Hardened Runtime or Library Validation to its vendor.",
        "critical",
        ("T1014", "T1562.001"),
        RISK_CATEGORY_PREDICATES["esf_bypass"],
    ),
    RecommendationRule(
        "review_sandbox_exceptions",
        "sandbox_escape",
        "Sandboxed app with broad exceptions is injectable",
        "The app is sandboxed but its profile allows unrestricted file reads or network access, "
        "and code can be loaded into it. Update it and review whether it needs those "
        "exceptions.",
        "high",
        ("T1612",),
        RISK_CATEGORY_PREDICATES["sandbox_escape"],
    ),
    RecommendationRule(
        "review_mdm_pppc",
        "mdm_risk",
        "MDM grants permissions to a scripting tool",
        "A management profile pre-approves privacy permissions for a terminal or script "
        "interpreter. Any script run through it inherits those permissions. Ask your MDM "
        "administrator to scope the PPPC payload to the specific tools that need it.",
        "high",
        ("T1548.004",),
        RISK_CATEGORY_PREDICATES["mdm_risk"],
    ),
    # ── Host settings ───────────────────────────────────────────────────────
    RecommendationRule(
        "enable_sip",
        "host_posture",
        "Turn System Integrity Protection back on",
        "SIP is disabled, so root can modify system files and protected locations. Restart "
        "into Recovery and run `csrutil enable`.",
        "critical",
        ("T1562.001",),
        "c.sip_enabled = false",
        target="host",
    ),
    RecommendationRule(
        "enable_gatekeeper",
        "host_posture",
        "Turn Gatekeeper back on",
        "Gatekeeper assessments are disabled, so downloaded apps run without signature or "
        "notarization checks. Run `sudo spctl --master-enable`.",
        "critical",
        ("T1553.001",),
        "c.gatekeeper_enabled = false",
        target="host",
    ),
    RecommendationRule(
        "enable_filevault",
        "host_posture",
        "Turn on FileVault",
        "The startup disk is not encrypted, so anyone with the hardware can read your files. "
        f"Enable FileVault in {_SETTINGS_PRIVACY} › FileVault and store the recovery key safely.",
        "high",
        ("T1200",),
        "c.filevault_enabled = false",
        target="host",
    ),
    RecommendationRule(
        "enable_screen_lock",
        "host_posture",
        "Require a password after sleep",
        "The Mac does not ask for a password after the screen saver or sleep. Enable it in "
        "System Settings › Lock Screen and set the delay to 5 seconds or less.",
        "high",
        ("T1200",),
        "c.screen_lock_enabled = false OR (c.screen_lock_enabled = true AND c.screen_lock_delay > 5)",
        target="host",
    ),
    RecommendationRule(
        "enable_firewall",
        "host_posture",
        "Turn on the application firewall",
        "The macOS application firewall is off, so every listening program accepts incoming "
        "connections. Turn it on in System Settings › Network › Firewall.",
        "medium",
        (),
        "EXISTS { MATCH (f:FirewallPolicy) WHERE f.enabled = false }",
        target="host",
    ),
    RecommendationRule(
        "disable_remote_login",
        "lateral_movement",
        "Remote Login (SSH) is on",
        "SSH accepts connections to this Mac. Turn off Remote Login in System Settings › "
        "General › Sharing unless you use it; if you do, disable password authentication and "
        "root login in /etc/ssh/sshd_config and restrict access to a dedicated group.",
        "medium",
        ("T1021.004",),
        "EXISTS { MATCH (s:RemoteAccessService {service: 'ssh', enabled: true}) }",
        target="host",
    ),
    RecommendationRule(
        "disable_screen_sharing",
        "lateral_movement",
        "Screen Sharing is on",
        "Screen Sharing (VNC) accepts connections to this Mac. Turn it off in System Settings "
        "› General › Sharing unless you rely on it, and limit it to specific users if you do.",
        "medium",
        ("T1021.005",),
        "EXISTS { MATCH (s:RemoteAccessService {service: 'screen_sharing', enabled: true}) }",
        target="host",
    ),
    RecommendationRule(
        "remove_nopasswd_sudo",
        "authorization_hardening",
        "Remove passwordless sudo rules",
        "A sudoers rule grants root without a password, so any code running as that account "
        "becomes root silently. Edit the rule with `sudo visudo` (or the file in "
        "/etc/sudoers.d) and remove NOPASSWD.",
        "high",
        ("T1548.003",),
        "EXISTS { MATCH (:SudoersRule {nopasswd: true}) }",
        target="host",
    ),
    RecommendationRule(
        "fix_critical_file_permissions",
        "file_acl_escalation",
        "Fix permissions on privileged files",
        "A file that controls privilege (sudoers, a LaunchDaemon, the authorization database, "
        "sshd_config or the system TCC store) is writable by a non-root user or group. Restore "
        "root:wheel ownership and remove the write bit or ACL entry.",
        "critical",
        ("T1098",),
        "EXISTS { MATCH (cf:CriticalFile) WHERE cf.is_writable_by_non_root = true "
        "AND cf.category IN ['tcc_database', 'sudoers', 'launch_daemon_dir', 'authorization_db', 'ssh_config'] }",
        target="host",
    ),
    RecommendationRule(
        "review_shell_profile_permissions",
        "shell_hooks",
        "Shell profile is writable by other users",
        "A shell start-up file (.zshrc, .zprofile, /etc/zshrc, …) can be written by a group or "
        "by everyone. Anything written there runs in every new terminal session. Set it to "
        "644 and owner-only write.",
        "medium",
        ("T1546.004",),
        "EXISTS { MATCH (cf:CriticalFile {category: 'shell_hook'}) "
        "WHERE cf.is_world_writable = true OR cf.is_group_writable = true }",
        target="host",
    ),
    RecommendationRule(
        "secure_boot_full",
        "host_posture",
        "Secure Boot is reduced",
        "Startup security is below Full, so unsigned or downgraded kernels and extensions can "
        "load. Restore Full Security in Startup Security Utility unless a kernel extension "
        "requires otherwise.",
        "medium",
        (),
        "c.secure_boot_level IS NOT NULL AND c.secure_boot_level <> 'full'",
        target="host",
    ),
]
_RECOMMENDATIONS.extend(_INVENTORY_RULES)


def infer(session: Session) -> int:
    """
    Create Recommendation nodes and HAS_RECOMMENDATION + MITIGATES edges.

    Returns the total number of HAS_RECOMMENDATION edges created.
    """
    total_edges = 0
    edge_failures: list[str] = []

    for rule in _RECOMMENDATIONS:
        _merge_recommendation_node(session, rule)
        _link_recommendation_techniques(session, rule)

    for rule in _RECOMMENDATIONS:
        try:
            total_edges += _create_recommendation_edges(session, rule)
        except Neo4jError as exc:
            edge_failures.append(f"{rule.key}: {exc}")
            logger.error(
                "Recommendation edge creation failed for key=%s: %s",
                rule.key,
                exc,
            )

    try:
        total_edges += create_patch_recommendations(session)
    except Neo4jError as exc:
        edge_failures.append(f"patch_cve: {exc}")
        logger.error("CVE patch recommendation creation failed: %s", exc)

    try:
        total_edges += create_nvd_update_recommendations(session)
    except Neo4jError as exc:
        edge_failures.append(f"patch_nvd: {exc}")
        logger.error("NVD update recommendation creation failed: %s", exc)

    if edge_failures:
        raise RuntimeError("Recommendation edge creation failed: " + "; ".join(edge_failures))
    return total_edges


def _merge_recommendation_node(session: Session, rule: RecommendationRule) -> None:
    session.run(
        """
        MERGE (r:Recommendation {key: $key})
        SET r.category = $category,
            r.title    = $title,
            r.text     = $text,
            r.priority = $priority,
            r.scope    = $scope
        """,
        key=rule.key,
        category=rule.category,
        title=rule.title,
        text=rule.text,
        priority=rule.priority,
        scope=rule.target,
    )


def _link_recommendation_techniques(
    session: Session,
    rule: RecommendationRule,
) -> None:
    for tid in rule.technique_ids:
        session.run(
            """
            MATCH (r:Recommendation {key: $key})
            MATCH (t:AttackTechnique {technique_id: $tid})
            MERGE (r)-[:MITIGATES]->(t)
            """,
            key=rule.key,
            tid=tid,
        )


def _create_recommendation_edges(
    session: Session,
    rule: RecommendationRule,
) -> int:
    template = (
        _HOST_RECOMMENDATION_TEMPLATE if rule.target == "host" else _APP_RECOMMENDATION_TEMPLATE
    )
    cypher = template.format(condition=rule.condition)
    result = session.run(cast(Any, cypher), key=rule.key, attacker_id=ATTACKER_BUNDLE_ID)
    record = result.single()
    return int(record["n"]) if record else 0
