#!/usr/bin/env python3
"""
merge_scans.py — Import multiple Rootstock scan JSONs with hostname namespacing.

Enables multi-host correlation by importing scans from different macOS hosts
into the same Neo4j graph. Each scan creates a Computer node and all
Application/User nodes get linked via INSTALLED_ON/LOCAL_TO edges.

Usage:
    python3 graph/merge_scans.py --input scan1.json scan2.json [--neo4j bolt://localhost:7687]

Exit code 0 on success, 1 on failure.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from neo4j_connection import add_neo4j_args, connect_from_args
from models import ScanResult, ComputerData
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

from scan_loader import load_scan


def import_scan(session, scan: ScanResult) -> None:
    """Import a single scan with all its data."""
    hostname = scan.hostname

    # Report any collection errors from the scan
    if scan.errors:
        for err in scan.errors:
            print(
                f"  [{hostname}] WARNING: {err.source}: {err.message}", file=sys.stderr
            )

    # Computer node with posture data
    computer = ComputerData(
        hostname=hostname,
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
    )

    # All data imports
    n_apps = import_applications(session, scan.applications, scan.scan_id)
    grants_linked, _ = import_tcc_grants(session, scan.tcc_grants, scan.scan_id)
    import_entitlements(session, scan.applications, scan.scan_id)
    import_signed_by_team(session)
    import_certificate_authorities(session, scan.applications, scan.scan_id)
    import_xpc_services(session, scan.xpc_services)
    import_keychain_items(session, scan.keychain_acls, scan.scan_id)
    import_mdm_profiles(session, scan.mdm_profiles)
    import_launch_items(session, scan.launch_items, scan.scan_id)
    import_local_groups(session, scan.local_groups, scan.scan_id)
    import_remote_access_services(session, scan.remote_access_services)
    import_firewall_status(session, scan.firewall_status, scan.scan_id)
    import_login_sessions(session, scan.login_sessions, hostname)
    import_authorization_rights(session, scan.authorization_rights)
    import_authorization_plugins(session, scan.authorization_plugins)
    import_system_extensions(session, scan.system_extensions)
    import_sudoers_rules(session, scan.sudoers_rules)
    import_running_processes(session, scan.running_processes, scan.scan_id)
    import_user_details(session, scan.user_details)
    import_file_acls(session, scan.file_acls)

    # AD binding, Kerberos artifacts, and sandbox profiles
    import_ad_binding(session, scan.ad_binding, hostname, scan.scan_id)
    import_kerberos_artifacts(session, scan.kerberos_artifacts, hostname, scan.scan_id)
    import_sandbox_profiles(session, scan.sandbox_profiles, scan.scan_id)

    # Computer linkage
    n_installed = import_installed_on(session, hostname, scan.scan_id)
    n_local_to = import_local_to(session, hostname, scan.scan_id)

    # Bluetooth devices
    import_bluetooth_devices(session, scan.bluetooth_devices, hostname, scan.scan_id)

    print(
        f"  [{hostname}] {n_apps} apps, {grants_linked} grants, "
        f"{n_installed} INSTALLED_ON, {n_local_to} LOCAL_TO"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Import multiple Rootstock scans for multi-host correlation"
    )
    parser.add_argument(
        "--input", nargs="+", required=False, default=[], help="Scan JSON file(s)"
    )
    parser.add_argument("--input-dir", help="Directory of scan JSON files to import")
    add_neo4j_args(parser)
    args = parser.parse_args()

    input_paths = list(args.input)
    if args.input_dir:
        dir_path = Path(args.input_dir)
        if not dir_path.is_dir():
            print(f"ERROR: Not a directory: {dir_path}", file=sys.stderr)
            return 1
        input_paths.extend(str(p) for p in sorted(dir_path.glob("*.json")))

    if not input_paths:
        print("ERROR: No input files. Use --input or --input-dir.", file=sys.stderr)
        return 1

    scans = []
    for path_str in input_paths:
        path = Path(path_str)
        if not path.exists():
            print(f"ERROR: File not found: {path}", file=sys.stderr)
            return 1
        scan = load_scan(path)
        if scan is None:
            return 1
        scans.append(scan)

    # Check for hostname collisions — error out to prevent data overwrite
    hostnames = [s.hostname for s in scans]
    if len(set(hostnames)) != len(hostnames):
        from collections import Counter

        dupes = [h for h, c in Counter(hostnames).items() if c > 1]
        print(
            f"ERROR: Duplicate hostnames detected: {dupes}. "
            f"Each scan must have a unique hostname to prevent data overwrite. "
            f"Use different hostnames or import one scan at a time.",
            file=sys.stderr,
        )
        return 1

    driver = connect_from_args(args)
    print(f"Importing {len(scans)} scan(s)...")

    with driver.session() as session:
        for scan in scans:
            import_scan(session, scan)

    driver.close()
    print(f"\nMerged {len(scans)} scans from hosts: {', '.join(hostnames)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
