"""import_nodes_services.py - XPC, launch items, MDM, and keychain imports."""

from __future__ import annotations

import logging

from neo4j import Session

from models import (
    XPCServiceData,
    KeychainItemData,
    MDMProfileData,
    LaunchItemData,
)

logger = logging.getLogger(__name__)


def import_xpc_services(
    session: Session, services: list[XPCServiceData]
) -> tuple[int, int]:
    """
    MERGE XPC_Service nodes and COMMUNICATES_WITH edges.

    COMMUNICATES_WITH edges are created when an Application has an Entitlement
    whose name exactly matches one of the service's mach_service names - indicating
    the application explicitly references that service by name.

    Returns (xpc_nodes, communicates_with_edges).
    """
    if not services:
        return 0, 0

    records = _xpc_service_records(services)
    _merge_xpc_service_nodes(session, records)
    comm_edges = _link_xpc_communicates_with_edges(session, records)
    return len(services), comm_edges


def _xpc_service_records(services: list[XPCServiceData]) -> list[dict[str, object]]:
    return [
        {
            "label": service.label,
            "path": service.path,
            "program": service.program,
            "type": service.type,
            "user": service.user,
            "run_at_load": service.run_at_load,
            "keep_alive": service.keep_alive,
            "mach_services": service.mach_services,
            "entitlements": service.entitlements,
            "has_client_verification": service.has_client_verification,
        }
        for service in services
    ]


def _merge_xpc_service_nodes(
    session: Session,
    records: list[dict[str, object]],
) -> None:
    session.run(
        """
        UNWIND $records AS r
        MERGE (x:XPC_Service {label: r.label})
        SET x.path          = r.path,
            x.program       = r.program,
            x.type          = r.type,
            x.user          = r.user,
            x.run_at_load   = r.run_at_load,
            x.keep_alive    = r.keep_alive,
            x.mach_services = r.mach_services,
            x.entitlements  = r.entitlements,
            x.has_client_verification = r.has_client_verification
        """,
        records=records,
    )


def _link_xpc_communicates_with_edges(
    session: Session,
    records: list[dict[str, object]],
) -> int:
    result = session.run(
        """
        UNWIND $records AS r
        WITH r WHERE size(r.mach_services) > 0
        UNWIND r.mach_services AS svc_name
        MATCH (x:XPC_Service {label: r.label})
        MATCH (a:Application)-[:HAS_ENTITLEMENT]->(e:Entitlement {name: svc_name})
        MERGE (a)-[rel:COMMUNICATES_WITH {mach_service: svc_name}]->(x)
        RETURN count(rel) AS n
        """,
        records=records,
    )
    return result.single()["n"]


def import_launch_items(
    session: Session, items: list[LaunchItemData], scan_id: str | None = None
) -> tuple[int, int, int, int]:
    """
    MERGE LaunchItem nodes, User nodes (for RUNS_AS), and infer graph edges.

    Edges created:
      - (Application)-[:PERSISTS_VIA]->(LaunchItem): when an app's bundle path
        is a prefix of the launch item's program path
      - (LaunchItem)-[:RUNS_AS]->(User): when the item has a user field
      - (User)-[:CAN_HIJACK]->(LaunchItem): when a daemon binary is writable by non-root

    Returns (launch_item_nodes, persists_via_edges, runs_as_edges, can_hijack_edges).
    """
    if not items:
        return 0, 0, 0, 0

    records = _launch_item_records(items)
    _merge_launch_item_nodes(session, records)
    persists_count = _link_persistence_edges(session, records, scan_id)
    runs_count = _link_runs_as_edges(session, records)
    hijack_count = _link_launch_hijack_edges(session, records)

    return len(items), persists_count, runs_count, hijack_count


def _launch_item_records(items: list[LaunchItemData]) -> list[dict[str, object]]:
    return [
        {
            "label": i.label,
            "path": i.path,
            "type": i.type,
            "program": i.program,
            "run_at_load": i.run_at_load,
            "user": i.user,
            "plist_owner": i.plist_owner,
            "program_owner": i.program_owner,
            "plist_writable_by_non_root": i.plist_writable_by_non_root,
            "program_writable_by_non_root": i.program_writable_by_non_root,
        }
        for i in items
    ]


def _merge_launch_item_nodes(
    session: Session,
    records: list[dict[str, object]],
) -> None:
    session.run(
        """
        UNWIND $records AS r
        MERGE (l:LaunchItem {label: r.label})
        SET l.path       = r.path,
            l.type       = r.type,
            l.program    = r.program,
            l.run_at_load = r.run_at_load,
            l.user       = r.user,
            l.plist_owner = r.plist_owner,
            l.program_owner = r.program_owner,
            l.plist_writable_by_non_root = r.plist_writable_by_non_root,
            l.program_writable_by_non_root = r.program_writable_by_non_root
        """,
        records=records,
    )


def _link_persistence_edges(
    session: Session,
    records: list[dict[str, object]],
    scan_id: str | None,
) -> int:
    result = session.run(
        """
        UNWIND $records AS r
        WITH r WHERE r.program IS NOT NULL
        MATCH (l:LaunchItem {label: r.label})
        MATCH (a:Application)
        WHERE r.program STARTS WITH a.path
          AND ($scan_id IS NULL OR a.scan_id = $scan_id)
        MERGE (a)-[rel:PERSISTS_VIA]->(l)
        RETURN count(rel) AS n
        """,
        records=records,
        scan_id=scan_id,
    )
    return result.single()["n"]


def _link_runs_as_edges(session: Session, records: list[dict[str, object]]) -> int:
    result = session.run(
        """
        UNWIND $records AS r
        WITH r WHERE r.user IS NOT NULL
        MATCH (l:LaunchItem {label: r.label})
        MERGE (u:User {name: r.user})
        MERGE (l)-[rel:RUNS_AS]->(u)
        RETURN count(rel) AS n
        """,
        records=records,
    )
    return result.single()["n"]


def _link_launch_hijack_edges(
    session: Session,
    records: list[dict[str, object]],
) -> int:
    result = session.run(
        """
        UNWIND $records AS r
        WITH r WHERE r.type = 'daemon'
          AND r.program_writable_by_non_root = true
        MATCH (l:LaunchItem {label: r.label})
        MATCH (u:User)-[:MEMBER_OF]->(:LocalGroup {name: 'admin'})
        MERGE (u)-[rel:CAN_HIJACK]->(l)
        SET rel.reason = 'program_writable_by_non_root'
        RETURN count(rel) AS n
        """,
        records=records,
    )
    return result.single()["n"]


def import_mdm_profiles(
    session: Session, profiles: list[MDMProfileData]
) -> tuple[int, int]:
    """
    MERGE MDM_Profile nodes and CONFIGURES relationships to TCC_Permission nodes.

    CONFIGURES edges carry bundle_id and allowed properties so callers can
    identify which applications have MDM-managed TCC access and whether it was
    granted or denied.

    Returns (mdm_profile_nodes, configures_edges).
    """
    if not profiles:
        return 0, 0

    profile_records = _mdm_profile_records(profiles)
    _merge_mdm_profile_nodes(session, profile_records)

    policy_records = _mdm_policy_records(profiles)
    if not policy_records:
        return len(profiles), 0

    edges = _link_mdm_configures_edges(session, policy_records)
    return len(profiles), edges


def _mdm_profile_records(profiles: list[MDMProfileData]) -> list[dict[str, object]]:
    return [
        {
            "identifier": profile.identifier,
            "display_name": profile.display_name,
            "organization": profile.organization,
            "install_date": profile.install_date,
        }
        for profile in profiles
    ]


def _merge_mdm_profile_nodes(
    session: Session,
    records: list[dict[str, object]],
) -> None:
    session.run(
        """
        UNWIND $records AS r
        MERGE (m:MDM_Profile {identifier: r.identifier})
        SET m.display_name = r.display_name,
            m.organization = r.organization,
            m.install_date = r.install_date
        """,
        records=records,
    )


def _mdm_policy_records(profiles: list[MDMProfileData]) -> list[dict[str, object]]:
    return [
        {
            "profile_identifier": profile.identifier,
            "service": policy.service,
            "bundle_id": policy.client_bundle_id,
            "allowed": policy.allowed,
        }
        for profile in profiles
        for policy in profile.tcc_policies
    ]


def _link_mdm_configures_edges(
    session: Session,
    records: list[dict[str, object]],
) -> int:
    result = session.run(
        """
        UNWIND $records AS r
        MATCH (m:MDM_Profile {identifier: r.profile_identifier})
        MERGE (t:TCC_Permission {service: r.service})
        ON CREATE SET t.display_name = r.service
        MERGE (m)-[rel:CONFIGURES {bundle_id: r.bundle_id}]->(t)
        SET rel.allowed = r.allowed
        RETURN count(rel) AS n
        """,
        records=records,
    )
    return result.single()["n"]


def _keychain_sensitivity(kind: str, service: str | None) -> str:
    """Classify keychain item sensitivity based on kind and service patterns."""
    svc = (service or "").lower()
    if kind == "key":
        return "critical"
    if kind == "certificate":
        return "high"
    if "ssh" in svc or "private" in svc:
        return "critical"
    if kind == "internet_password":
        return "medium"
    return "low"


def import_keychain_items(
    session: Session, items: list[KeychainItemData], scan_id: str | None = None
) -> tuple[int, int]:
    """
    MERGE Keychain_Item nodes and CAN_READ_KEYCHAIN relationships.

    CAN_READ_KEYCHAIN is created when an Application's bundle_id appears in
    a keychain item's trusted_apps list (i.e., the app is explicitly granted
    access without prompting the user).

    Returns (keychain_item_nodes, can_read_keychain_edges).
    """
    if not items:
        return 0, 0

    records = _keychain_item_records(items)
    _merge_keychain_item_nodes(session, records)
    edges = _link_can_read_keychain_edges(session, records, scan_id)
    return len(records), edges


def _keychain_item_records(items: list[KeychainItemData]) -> list[dict[str, object]]:
    return [
        {
            "label": item.label,
            "kind": item.kind,
            "service": item.service,
            "access_group": item.access_group,
            "trusted_apps": item.trusted_apps,
            "sensitivity": _keychain_sensitivity(item.kind, item.service),
        }
        for item in items
    ]


def _merge_keychain_item_nodes(
    session: Session,
    records: list[dict[str, object]],
) -> None:
    session.run(
        """
        UNWIND $records AS r
        MERGE (k:Keychain_Item {label: r.label, kind: r.kind})
        SET k.service      = r.service,
            k.access_group = r.access_group,
            k.sensitivity  = r.sensitivity
        """,
        records=records,
    )


def _link_can_read_keychain_edges(
    session: Session,
    records: list[dict[str, object]],
    scan_id: str | None,
) -> int:
    result = session.run(
        """
        UNWIND $records AS r
        WITH r WHERE size(r.trusted_apps) > 0
        UNWIND r.trusted_apps AS bundle_id
        MATCH (a:Application {bundle_id: bundle_id})
        WHERE $scan_id IS NULL OR a.scan_id = $scan_id
        MATCH (k:Keychain_Item {label: r.label, kind: r.kind})
        MERGE (a)-[rel:CAN_READ_KEYCHAIN]->(k)
        RETURN count(rel) AS n
        """,
        records=records,
        scan_id=scan_id,
    )
    return result.single()["n"]
