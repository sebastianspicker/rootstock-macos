"""import_nodes_services.py — XPC, launch items, MDM, and keychain imports."""

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
    whose name exactly matches one of the service's mach_service names — indicating
    the application explicitly references that service by name.

    Returns (xpc_nodes, communicates_with_edges).
    """
    if not services:
        return 0, 0

    records = [
        {
            "label": s.label,
            "path": s.path,
            "program": s.program,
            "type": s.type,
            "user": s.user,
            "run_at_load": s.run_at_load,
            "keep_alive": s.keep_alive,
            "mach_services": s.mach_services,
            "entitlements": s.entitlements,
            "has_client_verification": s.has_client_verification,
        }
        for s in services
    ]

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

    # COMMUNICATES_WITH: Application has entitlement key matching a mach service name
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
    comm_edges = result.single()["n"]
    return len(services), comm_edges


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

    records = [
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

    # MERGE LaunchItem nodes
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

    # PERSISTS_VIA: Application's bundle path is a prefix of the LaunchItem program path
    persists_result = session.run(
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
    persists_count = persists_result.single()["n"]

    # RUNS_AS: LaunchItem → User (MERGE User node by name)
    runs_result = session.run(
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
    runs_count = runs_result.single()["n"]

    # CAN_HIJACK: User → LaunchItem where daemon binary is writable by non-root.
    # Only create edges from admin group members (who can actually exploit writability),
    # not from every User node in the graph (which includes system accounts).
    hijack_result = session.run(
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
    hijack_count = hijack_result.single()["n"]

    return len(items), persists_count, runs_count, hijack_count


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

    profile_records = [
        {
            "identifier": p.identifier,
            "display_name": p.display_name,
            "organization": p.organization,
            "install_date": p.install_date,
        }
        for p in profiles
    ]

    # MERGE MDM_Profile nodes
    session.run(
        """
        UNWIND $records AS r
        MERGE (m:MDM_Profile {identifier: r.identifier})
        SET m.display_name = r.display_name,
            m.organization = r.organization,
            m.install_date = r.install_date
        """,
        records=profile_records,
    )

    # Flatten TCC policies across all profiles
    policy_records = [
        {
            "profile_identifier": p.identifier,
            "service": policy.service,
            "bundle_id": policy.client_bundle_id,
            "allowed": policy.allowed,
        }
        for p in profiles
        for policy in p.tcc_policies
    ]

    if not policy_records:
        return len(profiles), 0

    # CONFIGURES: MDM_Profile → TCC_Permission
    # Also MERGE the TCC_Permission node in case it doesn't exist yet.
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
        records=policy_records,
    )
    edges = result.single()["n"]

    return len(profiles), edges


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

    records = [
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

    # MERGE Keychain_Item nodes (label + kind forms the composite identity)
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

    # CAN_READ_KEYCHAIN: Application → Keychain_Item where bundle_id is in trusted_apps
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
    edges = result.single()["n"]

    return len(records), edges
