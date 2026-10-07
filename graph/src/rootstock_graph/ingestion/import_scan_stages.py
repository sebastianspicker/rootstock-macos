"""Later-stage import phases for a scan: security, enrichment, computer, device identity."""

from __future__ import annotations

from ..models import ComputerData
from .import_nodes_core import computer_import_context, import_computer, import_installed_on
from .import_nodes_enrichment import (
    import_bluetooth_devices,
    import_file_acls,
    import_running_processes,
    import_user_details,
)
from .import_nodes_sandbox import import_sandbox_profiles
from .import_nodes_security import (
    import_authorization_plugins,
    import_authorization_rights,
    import_firewall_status,
    import_local_groups,
    import_login_sessions,
    import_remote_access_services,
    import_sudoers_rules,
    import_system_extensions,
)
from .import_nodes_security_enterprise import import_ad_binding, import_kerberos_artifacts
from .import_nodes_services import import_launch_items


def import_security_inventory(session, scan) -> None:
    """Import security and persistence records that depend on the core identities."""
    n_groups, n_member = import_local_groups(session, scan.local_groups, scan.scan_id)
    print(f"  Local groups:  {n_groups} nodes, {n_member} MEMBER_OF edges")

    n_items, n_persists, n_runs, n_hijack = import_launch_items(
        session, scan.launch_items, scan.scan_id
    )
    print(
        f"  Launch items:  {n_items} nodes, {n_persists} PERSISTS_VIA, {n_runs} RUNS_AS, {n_hijack} CAN_HIJACK edges"
    )

    n_remote, n_access = import_remote_access_services(session, scan.remote_access_services)
    print(f"  Remote access: {n_remote} nodes, {n_access} ACCESSIBLE_BY edges")

    n_fw, n_fw_rules = import_firewall_status(session, scan.firewall_status, scan.scan_id)
    print(f"  Firewall:      {n_fw} nodes, {n_fw_rules} HAS_FIREWALL_RULE edges")

    n_sessions, n_has_session = import_login_sessions(session, scan.login_sessions, scan.hostname)
    print(f"  Sessions:      {n_sessions} nodes, {n_has_session} HAS_SESSION edges")

    print(f"  Auth rights:   {import_authorization_rights(session, scan.authorization_rights)}")
    print(f"  Auth plugins:  {import_authorization_plugins(session, scan.authorization_plugins)}")
    print(f"  Sys extensions:{import_system_extensions(session, scan.system_extensions)}")

    n_sudoers, n_sudo_edges = import_sudoers_rules(session, scan.sudoers_rules, scan.scan_id)
    print(f"  Sudoers:       {n_sudoers} nodes, {n_sudo_edges} SUDO_NOPASSWD edges")


def import_enrichment_inventory(session, scan) -> None:
    n_running = import_running_processes(session, scan.running_processes, scan.scan_id)
    print(f"  Running procs: {n_running} apps flagged")

    n_user_details = import_user_details(session, scan.user_details)
    print(f"  User details:  {n_user_details}")

    n_file_acls = import_file_acls(session, scan.file_acls)
    print(f"  File ACLs:     {n_file_acls}")


def computer_context(scan, grants_linked: int, grants_skipped: int, import_status: str):
    return computer_import_context(
        scan,
        grants_linked=grants_linked,
        grants_skipped=grants_skipped,
        import_status=import_status,
    )


def import_computer_inventory(
    session, scan, grants_linked: int, grants_skipped: int, import_status: str
) -> None:
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
        computer_context(scan, grants_linked, grants_skipped, import_status),
    )
    n_installed = import_installed_on(session, scan.hostname, scan.scan_id)
    print(f"  Computer:      1 node, {n_installed} INSTALLED_ON edges")


def import_device_identity_inventory(session, scan) -> None:
    n_bt, n_paired = import_bluetooth_devices(
        session, scan.bluetooth_devices, scan.hostname, scan.scan_id
    )
    print(f"  BT devices:    {n_bt} nodes, {n_paired} PAIRED_WITH edges")

    n_adgroups, n_mapped = import_ad_binding(session, scan.ad_binding, scan.hostname, scan.scan_id)
    print(f"  AD binding:    {n_adgroups} ADGroup nodes, {n_mapped} MAPPED_TO edges")

    n_ka, n_found, n_cache, n_kt = import_kerberos_artifacts(
        session, scan.kerberos_artifacts, scan.hostname, scan.scan_id
    )
    print(
        f"  Kerberos:      {n_ka} artifacts, {n_found} FOUND_ON, {n_cache} HAS_KERBEROS_CACHE, {n_kt} HAS_KEYTAB edges"
    )

    n_sandbox, n_sandbox_edges = import_sandbox_profiles(
        session, scan.sandbox_profiles, scan.scan_id
    )
    print(f"  Sandbox:       {n_sandbox} profiles, {n_sandbox_edges} HAS_SANDBOX_PROFILE edges")
