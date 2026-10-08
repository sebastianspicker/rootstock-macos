#!/usr/bin/env python3
"""
rootstock-graph-import-scan - Import a Rootstock collector scan JSON into Neo4j.

Usage:
    rootstock-graph-import-scan --input scan.json
        [--neo4j bolt://localhost:7687]
        [--neo4j-user neo4j]
        [--neo4j-password <password>]  # or NEO4J_PASSWORD
        [--keep-previous-scans]  # keep earlier scans of this Mac (default: replace them;
                                 # same hostname and hardware UUID)

Exit code 0 on success, 1 on failure.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .import_nodes_certificates import import_certificate_authorities
from .import_nodes_core import (
    import_applications,
    import_local_to,
    import_signed_by_team,
)
from .import_nodes_permissions import import_entitlements, import_tcc_grants
from .import_nodes_services import (
    import_keychain_items,
    import_mdm_profiles,
    import_xpc_services,
)
from .import_scan_stages import (
    import_computer_inventory,
    import_device_identity_inventory,
    import_enrichment_inventory,
    import_host_evidence_inventory,
    import_security_inventory,
)
from ..constants import FDA_SERVICE
from ..neo4j import add_neo4j_args, connect_from_args
from .replace_host import add_replace_host_arg, replace_host_requested, replace_host_scans
from .scan_loader import load_scan

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
    "UnresolvedTCCGrant",
    "Process",
    "NetworkListener",
    "TrustedCertificate",
    "BrowserExtension",
    "InstalledPackage",
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
    "INSTANCE_OF",
    "PARENT_OF",
    "RUNS_ON",
    "LISTENS_ON",
    "EXPOSED_ON",
    "TRUSTS_CERTIFICATE",
    "SAME_CERTIFICATE",
    "HAS_EXTENSION",
    "INSTALLED_BY",
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
    "REFERENCES_TCC_PERMISSION",
    "HAS_CVE_CONTEXT",
]


@dataclass(frozen=True)
class ImportSummary:
    import_status: str
    grants_skipped: int
    node_counts: dict
    rel_counts: dict
    security: dict


def _query_present_counts(
    session,
    values: list[str],
    *,
    schema_query: str,
    parameter_name: str,
    record_key: str,
    count_statement: Callable[[str], str],
) -> dict[str, int]:
    counts = {value: 0 for value in values}
    present_values = {
        record[record_key] for record in session.run(schema_query, **{parameter_name: list(values)})
    }
    if not present_values:
        return counts

    count_query = " UNION ALL ".join(
        count_statement(value) for value in values if value in present_values
    )
    for record in session.run(count_query):
        counts[record[record_key]] = record["n"]
    return counts


def _node_count_statement(label: str) -> str:
    return f"CALL () {{ MATCH (n:{label}) RETURN count(n) AS n }} RETURN '{label}' AS label, n"


def _relationship_count_statement(rel_type: str) -> str:
    return (
        f"CALL () {{ MATCH ()-[r:{rel_type}]->() RETURN count(r) AS n }} "
        f"RETURN '{rel_type}' AS rel_type, n"
    )


def query_stats(session) -> tuple[dict, dict]:
    """Query post-import node and relationship counts. Returns (node_counts, rel_counts)."""
    node_counts = _query_present_counts(
        session,
        _NODE_LABELS,
        schema_query=("CALL db.labels() YIELD label WHERE label IN $node_labels RETURN label"),
        parameter_name="node_labels",
        record_key="label",
        count_statement=_node_count_statement,
    )
    rel_counts = _query_present_counts(
        session,
        _REL_TYPES,
        schema_query=(
            "CALL db.relationshipTypes() YIELD relationshipType AS rel_type "
            "WHERE rel_type IN $relationship_types RETURN rel_type"
        ),
        parameter_name="relationship_types",
        record_key="rel_type",
        count_statement=_relationship_count_statement,
    )
    return node_counts, rel_counts


def query_security_summary(session) -> dict:
    """Query security-relevant aggregate stats as smoke-test output."""
    fda = session.run(
        """
        MATCH (a:Application)-[:HAS_TCC_GRANT {allowed: true}]->(t:TCC_Permission {service: $fda_service})
        RETURN count(a) AS n
        """,
        fda_service=FDA_SERVICE,
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


def classify_import_status(collection_error_count: int, tcc_grants_skipped: int) -> str:
    return "partial" if collection_error_count > 0 or tcc_grants_skipped > 0 else "complete"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Import a Rootstock scan JSON into Neo4j")
    parser.add_argument("--input", required=True, help="Path to scan JSON file")
    add_neo4j_args(parser)
    add_replace_host_arg(parser)
    parser.add_argument("--verbose", "-v", action="store_true")
    return parser


def _print_scan_contents(scan) -> None:
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
    ad_status = "  yes" if scan.ad_binding and scan.ad_binding.is_bound else "   no"
    print(f"  AD binding:       {ad_status}")
    print(f"  Kerberos arts:    {len(scan.kerberos_artifacts):>5}")
    print(f"  Sandbox profiles: {len(scan.sandbox_profiles):>5}")
    print(f"  Net listeners:    {len(scan.network_listeners):>5}")
    print(f"  Trusted certs:    {len(scan.certificate_trust_settings):>5}")
    print(f"  Browser exts:     {len(scan.browser_extensions):>5}")
    print(f"  Packages:         {len(scan.installed_packages):>5}")
    if scan.errors:
        print(f"  Collection errors:{len(scan.errors):>5}")
    print()


def _load_input_scan(input_arg: str):
    input_path = Path(input_arg)

    if not input_path.exists():
        print(f"ERROR: File not found: {input_path}", file=sys.stderr)
        return None

    print(f"Loading {input_path}...")
    return load_scan(input_path)


def _import_core_inventory(session, scan) -> tuple[int, int, str]:
    """Import identity-bearing core nodes first so later relationships can resolve."""
    n_apps = import_applications(session, scan.applications, scan.scan_id)
    print(f"  Applications:  {n_apps}")

    grants_linked, grants_skipped = import_tcc_grants(session, scan.tcc_grants, scan.scan_id)
    import_status = classify_import_status(len(scan.errors), grants_skipped)
    print(f"  TCC grants:    {grants_linked} linked, {grants_skipped} skipped (unresolved clients)")

    n_ents, n_ent_rels = import_entitlements(session, scan.applications, scan.scan_id)
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

    n_kc, n_kc_edges = import_keychain_items(session, scan.keychain_acls, scan.scan_id)
    print(f"  Keychain ACLs: {n_kc} nodes, {n_kc_edges} CAN_READ_KEYCHAIN edges")

    n_mdm, n_cfg = import_mdm_profiles(session, scan.mdm_profiles)
    print(f"  MDM profiles:  {n_mdm} nodes, {n_cfg} CONFIGURES edges")

    return grants_linked, grants_skipped, import_status


def _run_import(driver, scan, replace_host: bool = True) -> ImportSummary:
    """Run import phases in dependency order and summarize the committed graph."""
    print(f"--- Importing to Neo4j {'─' * 38}")
    with driver.session() as session:
        if replace_host:
            n_removed = replace_host_scans(session, scan.hostname, scan.scan_id, scan.hardware_uuid)
            print(f"  Replaced host: {n_removed} nodes removed from earlier scans")
        grants_linked, grants_skipped, import_status = _import_core_inventory(session, scan)
        import_security_inventory(session, scan)
        import_enrichment_inventory(session, scan)
        import_computer_inventory(session, scan, grants_linked, grants_skipped, import_status)
        import_host_evidence_inventory(session, scan)
        import_device_identity_inventory(session, scan)
        # Last: users are created by Kerberos/AD import and later inference, so LOCAL_TO
        # must see every user attached to this scan.
        n_local_to = import_local_to(session, scan.hostname, scan.scan_id)
        print(f"  Local users:   {n_local_to} LOCAL_TO edges")
        node_counts, rel_counts = query_stats(session)
        security = query_security_summary(session)

    return ImportSummary(
        import_status=import_status,
        grants_skipped=grants_skipped,
        node_counts=node_counts,
        rel_counts=rel_counts,
        security=security,
    )


def _print_import_summary(scan, summary: ImportSummary) -> None:
    total_nodes = sum(summary.node_counts.values())
    total_rels = sum(summary.rel_counts.values())
    print("\n" + "=" * 60)
    print(f"  IMPORT {summary.import_status.upper()}")
    print("=" * 60)
    print(f"  Total nodes:         {total_nodes:>5}")
    print(f"  Total relationships: {total_rels:>5}")
    if summary.import_status == "partial":
        print("─" * 60)
        print(f"  Collection errors:   {len(scan.errors):>5}")
        print(f"  TCC grants skipped:  {summary.grants_skipped:>5}")
        print(
            "WARNING: import completed with partial source data; "
            "pipeline will continue, but graph results may be incomplete.",
            file=sys.stderr,
        )
    print("─" * 60)
    print(
        f"  Apps: {summary.node_counts['Application']}  "
        f"Entitlements: {summary.node_counts['Entitlement']}  "
        f"XPC: {summary.node_counts['XPC_Service']}  "
        f"Launch: {summary.node_counts['LaunchItem']}"
    )
    print(
        f"  Keychain: {summary.node_counts['Keychain_Item']}  "
        f"MDM: {summary.node_counts['MDM_Profile']}  "
        f"Groups: {summary.node_counts['LocalGroup']}"
    )
    print("─" * 60)
    print("  Security Summary:")
    print(f"    Full Disk Access apps: {summary.security['fda_apps']}")
    print(f"    Injectable apps:       {summary.security['injectable_apps']}")
    print(f"    Electron apps:         {summary.security['electron_apps']}")
    print("=" * 60)


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    scan = _load_input_scan(args.input)
    if scan is None:
        return 1

    _print_scan_contents(scan)
    driver = connect_from_args(args)
    summary = _run_import(driver, scan, replace_host=replace_host_requested(args))
    driver.close()
    _print_import_summary(scan, summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
