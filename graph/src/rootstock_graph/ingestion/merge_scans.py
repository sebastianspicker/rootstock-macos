#!/usr/bin/env python3
"""
rootstock-graph-merge-scans - Import multiple Rootstock scan JSONs with hostname namespacing.

Enables multi-host correlation by importing scans from different macOS hosts
into the same Neo4j graph. Each scan creates a Computer node and all
Application/User nodes get linked via INSTALLED_ON/LOCAL_TO edges.

Usage:
    rootstock-graph-merge-scans --input scan1.json scan2.json [--neo4j bolt://localhost:7687]

Exit code 0 on success, 1 on failure.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from . import import_nodes_certificates
from . import import_nodes_core
from . import import_nodes_enrichment
from . import import_nodes_permissions
from . import import_nodes_sandbox
from . import import_nodes_security
from . import import_nodes_security_enterprise
from . import import_nodes_services
from ..neo4j import add_neo4j_args, connect_from_args
from ..models import ScanResult, ComputerData

from .import_scan import classify_import_status
from .scan_loader import load_scan


def _report_scan_errors(scan: ScanResult) -> None:
    for err in scan.errors:
        print(f"  [{scan.hostname}] WARNING: {err.source}: {err.message}", file=sys.stderr)


def _scan_computer(scan: ScanResult) -> ComputerData:
    return ComputerData(
        hostname=scan.hostname,
        macos_version=scan.macos_version,
        scan_id=scan.scan_id,
        scanned_at=scan.timestamp,
        collector_version=scan.collector_version,
        elevation_is_root=scan.elevation.is_root,
        elevation_has_fda=scan.elevation.has_fda,
    )


def _import_scan_entities(session, scan: ScanResult) -> tuple[int, int, int]:
    """Import core, security and enrichment records (everything before the Computer node)."""
    n_apps = import_nodes_core.import_applications(session, scan.applications, scan.scan_id)
    grants_linked, grants_skipped = import_nodes_permissions.import_tcc_grants(
        session, scan.tcc_grants, scan.scan_id
    )
    import_nodes_permissions.import_entitlements(session, scan.applications, scan.scan_id)
    import_nodes_core.import_signed_by_team(session)
    import_nodes_certificates.import_certificate_authorities(
        session, scan.applications, scan.scan_id
    )
    import_nodes_services.import_xpc_services(session, scan.xpc_services)
    import_nodes_services.import_keychain_items(session, scan.keychain_acls, scan.scan_id)
    import_nodes_services.import_mdm_profiles(session, scan.mdm_profiles)
    # Local groups first: launch-item hijack edges depend on admin membership.
    import_nodes_security.import_local_groups(session, scan.local_groups, scan.scan_id)
    import_nodes_services.import_launch_items(session, scan.launch_items, scan.scan_id)
    import_nodes_security.import_remote_access_services(session, scan.remote_access_services)
    import_nodes_security.import_firewall_status(session, scan.firewall_status, scan.scan_id)
    import_nodes_security.import_login_sessions(session, scan.login_sessions, scan.hostname)
    import_nodes_security.import_authorization_rights(session, scan.authorization_rights)
    import_nodes_security.import_authorization_plugins(session, scan.authorization_plugins)
    import_nodes_security.import_system_extensions(session, scan.system_extensions)
    import_nodes_security.import_sudoers_rules(session, scan.sudoers_rules)
    import_nodes_enrichment.import_running_processes(session, scan.running_processes, scan.scan_id)
    import_nodes_enrichment.import_user_details(session, scan.user_details)
    import_nodes_enrichment.import_file_acls(session, scan.file_acls)
    return n_apps, grants_linked, grants_skipped


def _import_device_identity(session, scan: ScanResult) -> None:
    """Import records attached to the Computer node (must run after import_computer)."""
    import_nodes_security_enterprise.import_ad_binding(
        session, scan.ad_binding, scan.hostname, scan.scan_id
    )
    import_nodes_security_enterprise.import_kerberos_artifacts(
        session, scan.kerberos_artifacts, scan.hostname, scan.scan_id
    )
    import_nodes_sandbox.import_sandbox_profiles(session, scan.sandbox_profiles, scan.scan_id)
    import_nodes_enrichment.import_bluetooth_devices(
        session, scan.bluetooth_devices, scan.hostname, scan.scan_id
    )


def import_scan(session, scan: ScanResult) -> None:
    """Import a single scan with all its data."""
    hostname = scan.hostname

    if scan.errors:
        _report_scan_errors(scan)

    n_apps, grants_linked, grants_skipped = _import_scan_entities(session, scan)
    import_status = classify_import_status(len(scan.errors), grants_skipped)
    import_nodes_core.import_computer(
        session,
        _scan_computer(scan),
        import_nodes_core.computer_import_context(
            scan,
            grants_linked=grants_linked,
            grants_skipped=grants_skipped,
            import_status=import_status,
        ),
    )
    _import_device_identity(session, scan)
    n_installed = import_nodes_core.import_installed_on(session, hostname, scan.scan_id)
    n_local_to = import_nodes_core.import_local_to(session, hostname, scan.scan_id)

    print(
        f"  [{hostname}] {n_apps} apps, {grants_linked} grants, "
        f"{n_installed} INSTALLED_ON, {n_local_to} LOCAL_TO"
    )


def main() -> int:
    args = _parse_args()
    input_paths = _input_paths_from_args(args)
    if input_paths is None:
        return 1

    scans = _load_input_scans(input_paths)
    if scans is None:
        return 1

    hostnames = [s.hostname for s in scans]
    if not _validate_unique_hostnames(hostnames):
        return 1

    driver = connect_from_args(args)
    _import_scans(driver, scans)
    print(f"\nMerged {len(scans)} scans from hosts: {', '.join(hostnames)}")
    return 0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Import multiple Rootstock scans for multi-host correlation"
    )
    parser.add_argument("--input", nargs="+", required=False, default=[], help="Scan JSON file(s)")
    parser.add_argument("--input-dir", help="Directory of scan JSON files to import")
    add_neo4j_args(parser)
    return parser.parse_args()


def _input_paths_from_args(args: argparse.Namespace) -> list[str] | None:
    input_paths = list(args.input)
    if args.input_dir:
        dir_path = Path(args.input_dir)
        if not dir_path.is_dir():
            print(f"ERROR: Not a directory: {dir_path}", file=sys.stderr)
            return None
        input_paths.extend(str(p) for p in sorted(dir_path.glob("*.json")))

    if not input_paths:
        print("ERROR: No input files. Use --input or --input-dir.", file=sys.stderr)
        return None
    return input_paths


def _load_input_scans(input_paths: list[str]) -> list[ScanResult] | None:
    scans = []
    for path_str in input_paths:
        path = Path(path_str)
        if not path.exists():
            print(f"ERROR: File not found: {path}", file=sys.stderr)
            return None
        scan = load_scan(path)
        if scan is None:
            return None
        scans.append(scan)
    return scans


def _validate_unique_hostnames(hostnames: list[str]) -> bool:
    if len(set(hostnames)) != len(hostnames):
        dupes = [h for h, c in Counter(hostnames).items() if c > 1]
        print(
            f"ERROR: Duplicate hostnames detected: {dupes}. "
            f"Each scan must have a unique hostname to prevent data overwrite. "
            f"Use different hostnames or import one scan at a time.",
            file=sys.stderr,
        )
        return False
    return True


def _import_scans(driver, scans: list[ScanResult]) -> None:
    print(f"Importing {len(scans)} scan(s)...")

    with driver.session() as session:
        for scan in scans:
            import_scan(session, scan)

    driver.close()


if __name__ == "__main__":
    sys.exit(main())
