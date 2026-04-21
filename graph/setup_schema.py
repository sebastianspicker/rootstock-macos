#!/usr/bin/env python3
"""
setup_schema.py — Create Neo4j indexes and constraints for the Rootstock graph.

Run once before the first import, or re-run safely (all statements use IF NOT EXISTS).

Usage:
    python3 graph/setup_schema.py [--neo4j bolt://localhost:7687] [--username neo4j] [--password rootstock]
"""

from __future__ import annotations

import argparse
import sys

from neo4j_connection import add_neo4j_args, connect_from_args

# ── Schema definitions ───────────────────────────────────────────────────────

# Uniqueness constraints (also create implicit indexes)
CONSTRAINTS = [
    ("app_key_unique", "Application", "a.app_key"),
    ("tcc_service_unique", "TCC_Permission", "t.service"),
    ("ent_name_unique", "Entitlement", "e.name"),
    ("xpc_label_unique", "XPC_Service", "x.label"),
    ("launch_label_unique", "LaunchItem", "l.label"),
    ("mdm_id_unique", "MDM_Profile", "m.identifier"),
    ("user_name_unique", "User", "u.name"),
    ("group_name_unique", "LocalGroup", "g.name"),
    ("remote_svc_unique", "RemoteAccessService", "r.service"),
    ("firewall_name_unique", "FirewallPolicy", "f.name"),
    ("auth_right_unique", "AuthorizationRight", "ar.name"),
    ("auth_plugin_unique", "AuthorizationPlugin", "ap.name"),
    ("sysext_id_unique", "SystemExtension", "se.identifier"),
    ("sudoers_key_unique", "SudoersRule", "sr.key"),
    ("critfile_path_unique", "CriticalFile", "cf.path"),
    ("computer_key_unique", "Computer", "c.computer_key"),
    ("ca_sha256_unique", "CertificateAuthority", "ca.sha256"),
    ("bt_device_addr_unique", "BluetoothDevice", "bt.address"),
    ("kerberos_path_unique", "KerberosArtifact", "ka.path"),
    ("adgroup_name_unique", "ADGroup", "ag.name"),
    ("vuln_cve_unique", "Vulnerability", "v.cve_id"),
    ("technique_id_unique", "AttackTechnique", "t.technique_id"),
    ("sandbox_profile_key_unique", "SandboxProfile", "sp.profile_key"),
    ("ad_user_sid_unique", "ADUser", "u.object_id"),
    ("threat_group_id_unique", "ThreatGroup", "g.group_id"),
    ("cwe_id_unique", "CWE", "c.cwe_id"),
    ("recommendation_key_unique", "Recommendation", "r.key"),
]

# Composite uniqueness constraint (Keychain items keyed by label + kind)
COMPOSITE_CONSTRAINTS = [
    ("keychain_label_kind_unique", "Keychain_Item", "k.label", "k.kind"),
    ("session_terminal_hostname_unique", "LoginSession", "s.terminal", "s.hostname"),
]

LEGACY_CONSTRAINTS = [
    "app_bundle_unique",
    "application_bundle_id",
    "computer_hostname_unique",
    "sandbox_bundle_unique",
    "session_terminal_unique",
    "keychain_item_label",
]

# Additional indexes for query performance (beyond what constraints provide)
INDEXES = [
    ("app_team_id", "Application", "a.team_id"),
    ("app_bundle_id", "Application", "a.bundle_id"),
    ("app_scan_id", "Application", "a.scan_id"),
    ("app_owned", "Application", "a.owned"),
    ("app_tier", "Application", "a.tier"),
    ("app_is_electron", "Application", "a.is_electron"),
    ("app_hardened_runtime", "Application", "a.hardened_runtime"),
    ("app_library_validation", "Application", "a.library_validation"),
    ("app_is_running", "Application", "a.is_running"),
    ("app_is_sandboxed", "Application", "a.is_sandboxed"),
    ("vuln_cvss", "Vulnerability", "v.cvss_score"),
    ("vuln_epss", "Vulnerability", "v.epss_score"),
    ("vuln_kev", "Vulnerability", "v.in_kev"),
    ("app_risk_score", "Application", "a.risk_score"),
    ("computer_hostname", "Computer", "c.hostname"),
    ("sandbox_bundle_id", "SandboxProfile", "sp.bundle_id"),
]


def apply_schema(session) -> None:
    """Apply the current Rootstock schema to an open Neo4j session."""
    for name in LEGACY_CONSTRAINTS:
        session.run(f"DROP CONSTRAINT {name} IF EXISTS")

    for name, label, prop in CONSTRAINTS:
        var = prop.split(".")[0]
        prop_name = prop.split(".")[1]
        stmt = (
            f"CREATE CONSTRAINT {name} IF NOT EXISTS "
            f"FOR ({var}:{label}) REQUIRE {var}.{prop_name} IS UNIQUE"
        )
        session.run(stmt)

    for name, label, *props in COMPOSITE_CONSTRAINTS:
        var = props[0].split(".")[0]
        prop_list = ", ".join(props)
        stmt = (
            f"CREATE CONSTRAINT {name} IF NOT EXISTS "
            f"FOR ({var}:{label}) REQUIRE ({prop_list}) IS UNIQUE"
        )
        session.run(stmt)

    for name, label, prop in INDEXES:
        var = prop.split(".")[0]
        prop_name = prop.split(".")[1]
        stmt = (
            f"CREATE INDEX {name} IF NOT EXISTS "
            f"FOR ({var}:{label}) ON ({var}.{prop_name})"
        )
        session.run(stmt)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create Neo4j schema (indexes + constraints) for Rootstock"
    )
    add_neo4j_args(parser)
    args = parser.parse_args()

    driver = connect_from_args(args)

    print("Creating schema...")
    with driver.session() as session:
        apply_schema(session)
        for name, label, prop in CONSTRAINTS:
            print(f"  ✓ UNIQUE {label}.{prop.split('.')[1]}")
        for name, label, *props in COMPOSITE_CONSTRAINTS:
            prop_names = ", ".join(p.split(".")[1] for p in props)
            print(f"  ✓ UNIQUE {label}.({prop_names})")
        for name, label, prop in INDEXES:
            print(f"  ✓ INDEX  {label}.{prop.split('.')[1]}")

    driver.close()
    print("Schema setup complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
