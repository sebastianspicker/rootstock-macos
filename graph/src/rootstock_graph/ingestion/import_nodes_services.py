"""import_nodes_services.py - XPC, launch items, MDM, and keychain imports."""

from __future__ import annotations

import logging

from neo4j import Session

from ..models import (
    XPCServiceData,
    KeychainItemData,
    MDMProfileData,
    LaunchItemData,
)
from .path_classification import program_in_user_writable_location

from .launch_item_facts import dyld_environment_entries, dyld_injection, launch_item_key

logger = logging.getLogger(__name__)


def import_xpc_services(session: Session, services: list[XPCServiceData]) -> tuple[int, int]:
    """
    MERGE XPC_Service nodes (keyed by plist path) and COMMUNICATES_WITH edges.

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
        MERGE (x:XPC_Service {path: r.path})
        SET x.label         = r.label,
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
        MATCH (x:XPC_Service {path: r.path})
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

    A LaunchItem is keyed by ``item_key = "<type>:<path>:<label>"``: one plist is one
    job, and two plists that share a label (a sysdiagnose collision) stay two nodes.

    Edges created:
      - (Application)-[:PERSISTS_VIA]->(LaunchItem): when an app's bundle path is a
        prefix of the launch item's program path (``match: 'program_path'``), when
        the program is signed by the app's team (``match: 'team_id'``), when the
        item label is namespaced under the app's bundle id (``match: 'label'``), or
        when the item is embedded in the app bundle (``match: 'bundle_path'``)
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
            "item_key": launch_item_key(i.type, i.path, i.label),
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
            "program_team_id": i.program_team_id,
            "program_signing_id": i.program_signing_id,
            "program_arguments": i.program_arguments,
            "environment_variable_names": i.environment_variable_names,
            "dyld_environment": dyld_environment_entries(i.dyld_environment),
            "launchd_dyld_injection": dyld_injection(i.dyld_environment),
            "triggers": list(i.triggers),
            "interval_seconds": i.interval_seconds,
            "session_type": i.session_type,
            "disabled": i.disabled,
            "loaded": i.loaded,
            "program_exists": i.program_exists,
            "program_sha256": i.program_sha256,
            "plist_modified": i.plist_modified,
            "bundle_path": i.bundle_path,
            "program_in_user_writable_location": program_in_user_writable_location(i.program),
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
        MERGE (l:LaunchItem {item_key: r.item_key})
        SET l.label      = r.label,
            l.path       = r.path,
            l.type       = r.type,
            l.program    = r.program,
            l.run_at_load = r.run_at_load,
            l.user       = r.user,
            l.plist_owner = r.plist_owner,
            l.program_owner = r.program_owner,
            l.plist_writable_by_non_root = r.plist_writable_by_non_root,
            l.program_writable_by_non_root = r.program_writable_by_non_root,
            l.program_team_id = r.program_team_id,
            l.program_signing_id = r.program_signing_id,
            l.program_arguments = r.program_arguments,
            l.environment_variable_names = r.environment_variable_names,
            l.dyld_environment = r.dyld_environment,
            l.launchd_dyld_injection = r.launchd_dyld_injection,
            l.triggers = r.triggers,
            l.interval_seconds = r.interval_seconds,
            l.session_type = r.session_type,
            l.disabled = r.disabled,
            l.loaded = r.loaded,
            l.program_exists = r.program_exists,
            l.program_sha256 = r.program_sha256,
            l.plist_modified = r.plist_modified,
            l.bundle_path = r.bundle_path,
            l.program_in_user_writable_location = r.program_in_user_writable_location
        """,
        records=records,
    )


_PERSISTENCE_LINK_RULES: tuple[tuple[str, str], ...] = (
    (
        "program_path",
        """
        WITH r WHERE r.program IS NOT NULL
        MATCH (l:LaunchItem {item_key: r.item_key})
        MATCH (a:Application)
        WHERE r.program STARTS WITH a.path + '/'
        """,
    ),
    # A helper signed by the same Developer ID team as an installed third-party app
    # belongs to that vendor; Apple's own daemons carry no team id and are skipped.
    (
        "team_id",
        """
        WITH r WHERE r.program_team_id IS NOT NULL
        MATCH (l:LaunchItem {item_key: r.item_key})
        MATCH (a:Application {team_id: r.program_team_id})
        WHERE NOT coalesce(a.is_system, false)
        """,
    ),
    # `us.zoom.xos.ZoomDaemon` under `us.zoom.xos`: a label namespaced under the app's
    # bundle id (or the app id under the label) names the same product. The shorter
    # (prefix) side needs at least three components, so a bare vendor prefix such as
    # `com.google` cannot tie every product of that vendor together. Heuristic match.
    (
        "label",
        """
        WITH r WHERE NOT r.label STARTS WITH 'com.apple.'
        MATCH (l:LaunchItem {item_key: r.item_key})
        MATCH (a:Application)
        WHERE NOT coalesce(a.is_system, false)
          AND NOT a.bundle_id STARTS WITH 'com.apple.'
          AND ((r.label STARTS WITH a.bundle_id + '.' AND size(split(a.bundle_id, '.')) >= 3)
            OR (a.bundle_id STARTS WITH r.label + '.' AND size(split(r.label, '.')) >= 3))
        """,
    ),
    # Items under `<App>.app/Contents/Library/{LaunchAgents,LaunchDaemons,LoginItems}`
    # carry the containing bundle; a nested helper app still belongs to the outer app.
    (
        "bundle_path",
        """
        WITH r WHERE r.bundle_path IS NOT NULL
        MATCH (l:LaunchItem {item_key: r.item_key})
        MATCH (a:Application)
        WHERE r.bundle_path = a.path OR r.bundle_path STARTS WITH a.path + '/'
        """,
    ),
)

# Rules whose edges only suggest ownership; the edge records ``confidence``.
_HEURISTIC_LINK_RULES = frozenset({"label"})


def _link_persistence_edges(
    session: Session,
    records: list[dict[str, object]],
    scan_id: str | None,
) -> int:
    """Create PERSISTS_VIA with a ``match`` reason; the strongest rule that fires wins.

    Edges from heuristic rules also carry ``confidence: 'heuristic'``.
    """
    total = 0
    for reason, match_clause in _PERSISTENCE_LINK_RULES:
        result = session.run(
            f"""
            UNWIND $records AS r
            {match_clause}
              AND ($scan_id IS NULL OR a.scan_id = $scan_id)
            MERGE (a)-[rel:PERSISTS_VIA]->(l)
            ON CREATE SET rel.match = $reason, rel.confidence = $confidence
            RETURN count(rel) AS n
            """,
            records=records,
            scan_id=scan_id,
            reason=reason,
            confidence="heuristic" if reason in _HEURISTIC_LINK_RULES else None,
        )
        total += result.single()["n"]
    return total


def _link_runs_as_edges(session: Session, records: list[dict[str, object]]) -> int:
    result = session.run(
        """
        UNWIND $records AS r
        WITH r WHERE r.user IS NOT NULL
        MATCH (l:LaunchItem {item_key: r.item_key})
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
        MATCH (l:LaunchItem {item_key: r.item_key})
        MATCH (u:User)-[:MEMBER_OF]->(:LocalGroup {name: 'admin'})
        MERGE (u)-[rel:CAN_HIJACK]->(l)
        SET rel.reason = 'program_writable_by_non_root'
        RETURN count(rel) AS n
        """,
        records=records,
    )
    return result.single()["n"]


def import_mdm_profiles(session: Session, profiles: list[MDMProfileData]) -> tuple[int, int]:
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
