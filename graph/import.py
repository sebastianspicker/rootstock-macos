#!/usr/bin/env python3
"""
import.py — Import a Rootstock collector scan JSON into Neo4j.

Usage:
    python3 graph/import.py --input scan.json [--neo4j bolt://localhost:7687] [--user neo4j] [--password rootstock]

Exit code 0 on success, 1 on failure.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from neo4j_connection import add_neo4j_args, connect_from_args
from scan_loader import load_scan
from import_nodes import (
    import_applications,
    import_tcc_grants,
    import_entitlements,
    import_signed_by_team,
    import_certificate_authorities,
    import_xpc_services,
    import_keychain_items,
    import_mdm_profiles,
    import_launch_items,
    import_local_groups,
    import_remote_access_services,
    import_firewall_status,
    import_login_sessions,
    import_authorization_rights,
    import_authorization_plugins,
    import_system_extensions,
    import_sudoers_rules,
    import_running_processes,
    import_file_acls,
    import_user_details,
    import_bluetooth_devices,
    import_computer,
    import_installed_on,
    import_local_to,
    import_ad_binding,
    import_kerberos_artifacts,
    import_sandbox_profiles,
)
from models import ComputerData

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


_NODE_LABELS = [
    "Application",
    "Entitlement",
    "TCC_Permission",
    "XPC_Service",
    "LaunchItem",
    "Keychain_Item",
    "MDM_Profile",
    "User",
    "LocalGroup",
    "RemoteAccessService",
    "FirewallPolicy",
    "LoginSession",
    "AuthorizationRight",
    "AuthorizationPlugin",
    "SystemExtension",
    "SudoersRule",
    "CriticalFile",
    "Computer",
    "CertificateAuthority",
    "BluetoothDevice",
    "KerberosArtifact",
    "ADGroup",
    "SandboxProfile",
]

_REL_TYPES = [
    # Import-created
    "HAS_TCC_GRANT",
    "HAS_ENTITLEMENT",
    "SIGNED_BY_SAME_TEAM",
    "COMMUNICATES_WITH",
    "PERSISTS_VIA",
    "RUNS_AS",
    "CAN_HIJACK",
    "CAN_READ_KEYCHAIN",
    "CONFIGURES",
    "MEMBER_OF",
    "ACCESSIBLE_BY",
    "HAS_FIREWALL_RULE",
    "HAS_SESSION",
    "SUDO_NOPASSWD",
    "INSTALLED_ON",
    "LOCAL_TO",
    "SIGNED_BY_CA",
    "ISSUED_BY",
    "PAIRED_WITH",
    # Inference-created
    "CAN_INJECT_INTO",
    "CHILD_INHERITS_TCC",
    "CAN_SEND_APPLE_EVENT",
    "HAS_TRANSITIVE_FDA",
    "CAN_WRITE",
    "PROTECTS",
    "CAN_MODIFY_TCC",
    "CAN_INJECT_SHELL",
    "CAN_CONTROL_VIA_A11Y",
    "CAN_BLIND_MONITORING",
    "CAN_DEBUG",
    "MDM_OVERGRANT",
    "SHARES_KEYCHAIN_GROUP",
    "CAN_CHANGE_PASSWORD",
    "MAPPED_TO",
    "FOUND_ON",
    "HAS_KERBEROS_CACHE",
    "HAS_KEYTAB",
    "CAN_READ_KERBEROS",
    "AD_USER_OF",
    "HAS_SANDBOX_PROFILE",
    "CAN_ESCAPE_SANDBOX",
    "CAN_ACCESS_MACH_SERVICE",
]


def query_stats(session) -> tuple[dict, dict]:
    """Query post-import node and relationship counts. Returns (node_counts, rel_counts)."""
    # Batch node counts into a single UNION ALL query
    node_query = " UNION ALL ".join(
        f"MATCH (n:{label}) RETURN '{label}' AS label, count(n) AS n"
        for label in _NODE_LABELS
    )
    node_counts = {label: 0 for label in _NODE_LABELS}
    for record in session.run(node_query):
        node_counts[record["label"]] = record["n"]

    # Batch relationship counts into a single UNION ALL query
    rel_query = " UNION ALL ".join(
        f"MATCH ()-[r:{rel_type}]->() RETURN '{rel_type}' AS rel_type, count(r) AS n"
        for rel_type in _REL_TYPES
    )
    rel_counts = {rel_type: 0 for rel_type in _REL_TYPES}
    for record in session.run(rel_query):
        rel_counts[record["rel_type"]] = record["n"]

    return node_counts, rel_counts


def query_security_summary(session) -> dict:
    """Query security-relevant aggregate stats as smoke-test output."""
    fda = session.run(
        """
        MATCH (a:Application)-[:HAS_TCC_GRANT {allowed: true}]->(t:TCC_Permission {service: 'kTCCServiceSystemPolicyAllFiles'})
        RETURN count(a) AS n
        """
    ).single()["n"]

    injectable = session.run(
        """
        MATCH (a:Application)
        WHERE coalesce(size(a.injection_methods), 0) > 0
        RETURN count(a) AS n
        """
    ).single()["n"]

    electron = session.run(
        "MATCH (a:Application {is_electron: true}) RETURN count(a) AS n"
    ).single()["n"]

    return {"fda_apps": fda, "injectable_apps": injectable, "electron_apps": electron}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Import a Rootstock scan JSON into Neo4j"
    )
    parser.add_argument("--input", required=True, help="Path to scan JSON file")
    add_neo4j_args(parser)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"ERROR: File not found: {input_path}", file=sys.stderr)
        return 1

    print(f"Loading {input_path}...")
    scan = load_scan(input_path)
    if scan is None:
        return 1

    print(f"\n{'=' * 60}")
    print(f"  ROOTSTOCK SCAN: {scan.hostname}")
    print(f"  Scan ID: {scan.scan_id}")
    print(f"{'=' * 60}")
    print(f"\n--- Scan Contents {'─' * 42}")
    print(f"  Applications:     {len(scan.applications):>5}")
    print(f"  TCC grants:       {len(scan.tcc_grants):>5}")
    print(f"  XPC services:     {len(scan.xpc_services):>5}")
    print(f"  Keychain ACLs:    {len(scan.keychain_acls):>5}")
    print(f"  MDM profiles:     {len(scan.mdm_profiles):>5}")
    print(f"  Launch items:     {len(scan.launch_items):>5}")
    print(f"  Local groups:     {len(scan.local_groups):>5}")
    print(f"  Remote access:    {len(scan.remote_access_services):>5}")
    print(f"  Firewall entries: {len(scan.firewall_status):>5}")
    print(f"  Login sessions:   {len(scan.login_sessions):>5}")
    print(f"  Auth rights:      {len(scan.authorization_rights):>5}")
    print(f"  Auth plugins:     {len(scan.authorization_plugins):>5}")
    print(f"  Sys extensions:   {len(scan.system_extensions):>5}")
    print(f"  Sudoers rules:    {len(scan.sudoers_rules):>5}")
    print(f"  Running procs:    {len(scan.running_processes):>5}")
    print(f"  File ACLs:        {len(scan.file_acls):>5}")
    print(f"  Bluetooth devs:   {len(scan.bluetooth_devices):>5}")
    print(
        f"  AD binding:       {'  yes' if scan.ad_binding and scan.ad_binding.is_bound else '   no'}"
    )
    print(f"  Kerberos arts:    {len(scan.kerberos_artifacts):>5}")
    print(f"  Sandbox profiles: {len(scan.sandbox_profiles):>5}")
    if scan.errors:
        print(f"  Collection errors:{len(scan.errors):>5}")
    print()

    driver = connect_from_args(args)

    print(f"--- Importing to Neo4j {'─' * 38}")
    with driver.session() as session:
        n_apps = import_applications(session, scan.applications, scan.scan_id)
        print(f"  Applications:  {n_apps}")

        grants_linked, grants_skipped = import_tcc_grants(
            session, scan.tcc_grants, scan.scan_id
        )
        print(
            f"  TCC grants:    {grants_linked} linked, {grants_skipped} skipped (path-only clients)"
        )

        n_ents, n_ent_rels = import_entitlements(
            session, scan.applications, scan.scan_id
        )
        print(f"  Entitlements:  {n_ents} nodes, {n_ent_rels} relationships")

        n_team_rels = import_signed_by_team(session)
        print(f"  Team edges:    {n_team_rels}")

        n_cas, n_signed_by, n_issued_by = import_certificate_authorities(
            session, scan.applications, scan.scan_id
        )
        print(
            f"  Cert authorities: {n_cas} nodes, {n_signed_by} SIGNED_BY_CA, {n_issued_by} ISSUED_BY edges"
        )

        n_xpc, n_comm = import_xpc_services(session, scan.xpc_services)
        print(f"  XPC services:  {n_xpc} nodes, {n_comm} COMMUNICATES_WITH edges")

        n_kc, n_kc_edges = import_keychain_items(
            session, scan.keychain_acls, scan.scan_id
        )
        print(f"  Keychain ACLs: {n_kc} nodes, {n_kc_edges} CAN_READ_KEYCHAIN edges")

        n_mdm, n_cfg = import_mdm_profiles(session, scan.mdm_profiles)
        print(f"  MDM profiles:  {n_mdm} nodes, {n_cfg} CONFIGURES edges")

        n_groups, n_member = import_local_groups(
            session, scan.local_groups, scan.scan_id
        )
        print(f"  Local groups:  {n_groups} nodes, {n_member} MEMBER_OF edges")

        n_items, n_persists, n_runs, n_hijack = import_launch_items(
            session, scan.launch_items, scan.scan_id
        )
        print(
            f"  Launch items:  {n_items} nodes, {n_persists} PERSISTS_VIA, {n_runs} RUNS_AS, {n_hijack} CAN_HIJACK edges"
        )

        n_remote, n_access = import_remote_access_services(
            session, scan.remote_access_services
        )
        print(f"  Remote access: {n_remote} nodes, {n_access} ACCESSIBLE_BY edges")

        n_fw, n_fw_rules = import_firewall_status(
            session, scan.firewall_status, scan.scan_id
        )
        print(f"  Firewall:      {n_fw} nodes, {n_fw_rules} HAS_FIREWALL_RULE edges")

        n_sessions, n_has_session = import_login_sessions(
            session, scan.login_sessions, scan.hostname
        )
        print(f"  Sessions:      {n_sessions} nodes, {n_has_session} HAS_SESSION edges")

        n_auth_rights = import_authorization_rights(session, scan.authorization_rights)
        print(f"  Auth rights:   {n_auth_rights}")

        n_auth_plugins = import_authorization_plugins(
            session, scan.authorization_plugins
        )
        print(f"  Auth plugins:  {n_auth_plugins}")

        n_sysext = import_system_extensions(session, scan.system_extensions)
        print(f"  Sys extensions:{n_sysext}")

        n_sudoers, n_sudo_edges = import_sudoers_rules(session, scan.sudoers_rules)
        print(f"  Sudoers:       {n_sudoers} nodes, {n_sudo_edges} SUDO_NOPASSWD edges")

        n_running = import_running_processes(
            session, scan.running_processes, scan.scan_id
        )
        print(f"  Running procs: {n_running} apps flagged")

        n_user_details = import_user_details(session, scan.user_details)
        print(f"  User details:  {n_user_details}")

        n_file_acls = import_file_acls(session, scan.file_acls)
        print(f"  File ACLs:     {n_file_acls}")

        computer = ComputerData(
            hostname=scan.hostname,
            macos_version=scan.macos_version,
            scan_id=scan.scan_id,
            scanned_at=scan.timestamp,
            collector_version=scan.collector_version,
            elevation_is_root=scan.elevation.is_root,
            elevation_has_fda=scan.elevation.has_fda,
        )
        import_computer(
            session,
            computer,
            gatekeeper_enabled=scan.gatekeeper_enabled,
            sip_enabled=scan.sip_enabled,
            filevault_enabled=scan.filevault_enabled,
            lockdown_mode_enabled=scan.lockdown_mode_enabled,
            bluetooth_enabled=scan.bluetooth_enabled,
            bluetooth_discoverable=scan.bluetooth_discoverable,
            screen_lock_enabled=scan.screen_lock_enabled,
            screen_lock_delay=scan.screen_lock_delay,
            display_sleep_timeout=scan.display_sleep_timeout,
            thunderbolt_security_level=scan.thunderbolt_security_level,
            secure_boot_level=scan.secure_boot_level,
            external_boot_allowed=scan.external_boot_allowed,
            icloud_signed_in=scan.icloud_signed_in,
            icloud_drive_enabled=scan.icloud_drive_enabled,
            icloud_keychain_enabled=scan.icloud_keychain_enabled,
            collection_error_count=len(scan.errors),
            collection_error_sources=[e.source for e in scan.errors]
            if scan.errors
            else [],
        )
        n_installed = import_installed_on(session, scan.hostname, scan.scan_id)
        n_local_to = import_local_to(session, scan.hostname, scan.scan_id)
        print(
            f"  Computer:      1 node, {n_installed} INSTALLED_ON, {n_local_to} LOCAL_TO edges"
        )

        n_bt, n_paired = import_bluetooth_devices(
            session, scan.bluetooth_devices, scan.hostname, scan.scan_id
        )
        print(f"  BT devices:    {n_bt} nodes, {n_paired} PAIRED_WITH edges")

        n_adgroups, n_mapped = import_ad_binding(
            session, scan.ad_binding, scan.hostname, scan.scan_id
        )
        print(
            f"  AD binding:    {n_adgroups} ADGroup nodes, {n_mapped} MAPPED_TO edges"
        )

        n_ka, n_found, n_cache, n_kt = import_kerberos_artifacts(
            session, scan.kerberos_artifacts, scan.hostname, scan.scan_id
        )
        print(
            f"  Kerberos:      {n_ka} artifacts, {n_found} FOUND_ON, {n_cache} HAS_KERBEROS_CACHE, {n_kt} HAS_KEYTAB edges"
        )

        n_sandbox, n_sandbox_edges = import_sandbox_profiles(
            session, scan.sandbox_profiles, scan.scan_id
        )
        print(
            f"  Sandbox:       {n_sandbox} profiles, {n_sandbox_edges} HAS_SANDBOX_PROFILE edges"
        )

        node_counts, rel_counts = query_stats(session)
        security = query_security_summary(session)

    driver.close()

    total_nodes = sum(node_counts.values())
    total_rels = sum(rel_counts.values())
    print("\n" + "=" * 60)
    print("  IMPORT COMPLETE")
    print("=" * 60)
    print(f"  Total nodes:         {total_nodes:>5}")
    print(f"  Total relationships: {total_rels:>5}")
    print("─" * 60)
    print(
        f"  Apps: {node_counts['Application']}  "
        f"Entitlements: {node_counts['Entitlement']}  "
        f"XPC: {node_counts['XPC_Service']}  "
        f"Launch: {node_counts['LaunchItem']}"
    )
    print(
        f"  Keychain: {node_counts['Keychain_Item']}  "
        f"MDM: {node_counts['MDM_Profile']}  "
        f"Groups: {node_counts['LocalGroup']}"
    )
    print("─" * 60)
    print("  Security Summary:")
    print(f"    Full Disk Access apps: {security['fda_apps']}")
    print(f"    Injectable apps:       {security['injectable_apps']}")
    print(f"    Electron apps:         {security['electron_apps']}")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
