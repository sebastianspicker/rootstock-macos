"""import_nodes_core.py - Core node imports (applications, TCC, entitlements, certificates)."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from neo4j import Session

from import_nodes_certificates import (
    import_certificate_authorities as import_certificate_authorities,
)
from import_nodes_sandbox import import_sandbox_profiles as import_sandbox_profiles
from models import (
    ApplicationData,
    TCCGrantData,
    ComputerData,
)

logger = logging.getLogger(__name__)

__all__ = [
    "ComputerImportContext",
    "import_applications",
    "import_certificate_authorities",
    "import_computer",
    "import_entitlements",
    "import_installed_on",
    "import_local_to",
    "import_sandbox_profiles",
    "import_signed_by_team",
    "import_tcc_grants",
]


@dataclass(frozen=True)
class ComputerImportContext:
    """Collector posture and import-quality fields attached to the host node."""

    gatekeeper_enabled: bool | None = None
    sip_enabled: bool | None = None
    filevault_enabled: bool | None = None
    lockdown_mode_enabled: bool | None = None
    bluetooth_enabled: bool | None = None
    bluetooth_discoverable: bool | None = None
    screen_lock_enabled: bool | None = None
    screen_lock_delay: int | None = None
    display_sleep_timeout: int | None = None
    thunderbolt_security_level: str | None = None
    secure_boot_level: str | None = None
    external_boot_allowed: bool | None = None
    icloud_signed_in: bool | None = None
    icloud_drive_enabled: bool | None = None
    icloud_keychain_enabled: bool | None = None
    collection_error_count: int = 0
    collection_error_sources: list[str] | None = None
    tcc_grants_linked: int = 0
    tcc_grants_skipped: int = 0
    import_status: str = "complete"


def computer_import_context(
    scan,
    grants_linked: int = 0,
    grants_skipped: int = 0,
    import_status: str = "complete",
) -> ComputerImportContext:
    """Build the shared host-posture context used by single and merged imports."""
    return ComputerImportContext(
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
        collection_error_sources=[error.source for error in scan.errors] if scan.errors else [],
        tcc_grants_linked=grants_linked,
        tcc_grants_skipped=grants_skipped,
        import_status=import_status,
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def import_computer(
    session: Session,
    computer: ComputerData,
    context: ComputerImportContext | None = None,
) -> int:
    """MERGE a Computer node representing the scanned host. Returns 1."""
    context = context or ComputerImportContext()
    params = _computer_import_params(computer, context)
    session.run(
        """
        MERGE (c:Computer {computer_key: $computer_key})
        SET c.macos_version = $macos_version,
            c.hostname = $hostname,
            c.scan_id = $scan_id,
            c.scanned_at = $scanned_at,
            c.collector_version = $collector_version,
            c.elevation_is_root = $elevation_is_root,
            c.elevation_has_fda = $elevation_has_fda,
            c.gatekeeper_enabled = $gatekeeper_enabled,
            c.sip_enabled = $sip_enabled,
            c.filevault_enabled = $filevault_enabled,
            c.lockdown_mode_enabled = $lockdown_mode_enabled,
            c.bluetooth_enabled = $bluetooth_enabled,
            c.bluetooth_discoverable = $bluetooth_discoverable,
            c.screen_lock_enabled = $screen_lock_enabled,
            c.screen_lock_delay = $screen_lock_delay,
            c.display_sleep_timeout = $display_sleep_timeout,
            c.thunderbolt_security_level = $thunderbolt_security_level,
            c.secure_boot_level = $secure_boot_level,
            c.external_boot_allowed = $external_boot_allowed,
            c.icloud_signed_in = $icloud_signed_in,
            c.icloud_drive_enabled = $icloud_drive_enabled,
            c.icloud_keychain_enabled = $icloud_keychain_enabled,
            c.collection_error_count = $collection_error_count,
            c.collection_error_sources = $collection_error_sources,
            c.tcc_grants_linked = $tcc_grants_linked,
            c.tcc_grants_skipped = $tcc_grants_skipped,
            c.import_status = $import_status
        """,
        **params,
    )
    return 1


def _computer_import_params(
    computer: ComputerData,
    context: ComputerImportContext,
) -> dict[str, object]:
    params = _computer_identity_params(computer)
    params.update(_computer_context_params(context))
    return params


def _computer_identity_params(computer: ComputerData) -> dict[str, object]:
    return {
        "computer_key": f"{computer.scan_id}:{computer.hostname}",
        "hostname": computer.hostname,
        "macos_version": computer.macos_version,
        "scan_id": computer.scan_id,
        "scanned_at": computer.scanned_at,
        "collector_version": computer.collector_version,
        "elevation_is_root": computer.elevation_is_root,
        "elevation_has_fda": computer.elevation_has_fda,
    }


def _computer_context_params(context: ComputerImportContext) -> dict[str, object]:
    return {
        "gatekeeper_enabled": context.gatekeeper_enabled,
        "sip_enabled": context.sip_enabled,
        "filevault_enabled": context.filevault_enabled,
        "lockdown_mode_enabled": context.lockdown_mode_enabled,
        "bluetooth_enabled": context.bluetooth_enabled,
        "bluetooth_discoverable": context.bluetooth_discoverable,
        "screen_lock_enabled": context.screen_lock_enabled,
        "screen_lock_delay": context.screen_lock_delay,
        "display_sleep_timeout": context.display_sleep_timeout,
        "thunderbolt_security_level": context.thunderbolt_security_level,
        "secure_boot_level": context.secure_boot_level,
        "external_boot_allowed": context.external_boot_allowed,
        "icloud_signed_in": context.icloud_signed_in,
        "icloud_drive_enabled": context.icloud_drive_enabled,
        "icloud_keychain_enabled": context.icloud_keychain_enabled,
        "collection_error_count": context.collection_error_count,
        "collection_error_sources": context.collection_error_sources or [],
        "tcc_grants_linked": context.tcc_grants_linked,
        "tcc_grants_skipped": context.tcc_grants_skipped,
        "import_status": context.import_status,
    }


def import_installed_on(session: Session, hostname: str, scan_id: str) -> int:
    """Create INSTALLED_ON edges from this scan's Application nodes to the Computer node. Returns edge count."""
    result = session.run(
        """
        MATCH (a:Application), (c:Computer {computer_key: $computer_key})
        WHERE a.scan_id = $scan_id
        MERGE (a)-[r:INSTALLED_ON]->(c)
        RETURN count(r) AS n
        """,
        computer_key=f"{scan_id}:{hostname}",
        scan_id=scan_id,
    )
    return result.single()["n"]


def import_local_to(session: Session, hostname: str, scan_id: str) -> int:
    """Create LOCAL_TO edges from Users linked to this scan's data to the Computer node.

    Discovers users via three sources:
    1. LaunchItem RUNS_AS chains (launch daemons/agents)
    2. LocalGroup memberships (MEMBER_OF edges)
    3. LoginSession HAS_SESSION edges

    Returns edge count.
    """
    result = session.run(
        """
        MATCH (c:Computer {computer_key: $computer_key})
        WITH c
        // Source 1: users with sessions on this host
        OPTIONAL MATCH (u1:User)-[:HAS_SESSION]->(:LoginSession {hostname: $hostname})
        WITH c, collect(DISTINCT u1) AS session_users
        // Source 2: users running launch items belonging to this scan's apps
        OPTIONAL MATCH (:Application {scan_id: $scan_id})-[:PERSISTS_VIA]->(:LaunchItem)-[:RUNS_AS]->(u2:User)
        WITH c, session_users, collect(DISTINCT u2) AS launch_users
        // Source 3: users in host-local groups discovered for this scan
        OPTIONAL MATCH (u3:User)-[m:MEMBER_OF]->(:LocalGroup)
        WHERE m.scan_id = $scan_id
        WITH c, session_users, launch_users, collect(DISTINCT u3) AS group_users
        WITH c, session_users + launch_users + group_users AS all_users
        UNWIND all_users AS u
        WITH DISTINCT c, u
        WHERE u IS NOT NULL
        MERGE (u)-[r:LOCAL_TO]->(c)
        RETURN count(r) AS n
        """,
        computer_key=f"{scan_id}:{hostname}",
        hostname=hostname,
        scan_id=scan_id,
    )
    return result.single()["n"]


def import_applications(
    session: Session, apps: list[ApplicationData], scan_id: str
) -> int:
    """MERGE Application nodes. Returns the number of apps processed."""
    if not apps:
        return 0

    now = _now_iso()
    records = [_application_record(app, scan_id, now) for app in apps]
    _merge_application_records(session, records)
    return len(records)


def _merge_application_records(
    session: Session,
    records: list[dict[str, object]],
) -> None:
    session.run(
        """
        UNWIND $records AS r
        MERGE (a:Application {app_key: r.app_key})
        SET a.bundle_id        = r.bundle_id,
            a.name             = r.name,
            a.path             = r.path,
            a.version          = r.version,
            a.team_id          = r.team_id,
            a.hardened_runtime = r.hardened_runtime,
            a.library_validation = r.library_validation,
            a.is_electron      = r.is_electron,
            a.is_system        = r.is_system,
            a.signed           = r.signed,
            a.code_signing_analysis_error = r.code_signing_analysis_error,
            a.is_sip_protected = r.is_sip_protected,
            a.is_sandboxed     = r.is_sandboxed,
            a.sandbox_exceptions = r.sandbox_exceptions,
            a.entitlements_available = r.entitlements_available,
            a.entitlement_extraction_error = r.entitlement_extraction_error,
            a.is_notarized     = r.is_notarized,
            a.is_adhoc_signed  = r.is_adhoc_signed,
            a.signing_certificate_cn = r.signing_certificate_cn,
            a.signing_certificate_sha256 = r.signing_certificate_sha256,
            a.certificate_expires = r.certificate_expires,
            a.is_certificate_expired = r.is_certificate_expired,
            a.certificate_chain_length = r.certificate_chain_length,
            a.certificate_trust_valid = r.certificate_trust_valid,
            a.injection_methods = r.injection_methods,
            a.launch_constraint_category = r.launch_constraint_category,
            a.has_quarantine_flag = r.has_quarantine_flag,
            a.quarantine_agent = r.quarantine_agent,
            a.quarantine_timestamp = r.quarantine_timestamp,
            a.was_user_approved = r.was_user_approved,
            a.was_translocated = r.was_translocated,
            a.scan_id          = r.scan_id,
            a.imported_at      = r.imported_at
        """,
        records=records,
    )


def _application_record(
    app: ApplicationData,
    scan_id: str,
    imported_at: str,
) -> dict[str, object]:
    return {
        "app_key": f"{scan_id}:{app.bundle_id}:{app.path}",
        "bundle_id": app.bundle_id,
        "name": app.name,
        "path": app.path,
        "version": app.version,
        "team_id": app.team_id,
        "hardened_runtime": app.hardened_runtime,
        "library_validation": app.library_validation,
        "is_electron": app.is_electron,
        "is_system": app.is_system,
        "signed": app.signed,
        "code_signing_analysis_error": app.code_signing_analysis_error,
        "is_sip_protected": app.is_sip_protected,
        "is_sandboxed": app.is_sandboxed,
        "sandbox_exceptions": app.sandbox_exceptions,
        "entitlements_available": app.entitlements_available,
        "entitlement_extraction_error": app.entitlement_extraction_error,
        "is_notarized": app.is_notarized,
        "is_adhoc_signed": app.is_adhoc_signed,
        "signing_certificate_cn": app.signing_certificate_cn,
        "signing_certificate_sha256": app.signing_certificate_sha256,
        "certificate_expires": app.certificate_expires,
        "is_certificate_expired": app.is_certificate_expired,
        "certificate_chain_length": app.certificate_chain_length,
        "certificate_trust_valid": app.certificate_trust_valid,
        "injection_methods": app.injection_methods,
        "launch_constraint_category": app.launch_constraint_category,
        **_application_quarantine_record(app),
        "scan_id": scan_id,
        "imported_at": imported_at,
    }


def _application_quarantine_record(app: ApplicationData) -> dict[str, object]:
    quarantine = app.quarantine_info
    if quarantine is None:
        return {
            "has_quarantine_flag": None,
            "quarantine_agent": None,
            "quarantine_timestamp": None,
            "was_user_approved": None,
            "was_translocated": None,
        }
    return {
        "has_quarantine_flag": quarantine.has_quarantine_flag,
        "quarantine_agent": quarantine.quarantine_agent,
        "quarantine_timestamp": quarantine.quarantine_timestamp,
        "was_user_approved": quarantine.was_user_approved,
        "was_translocated": quarantine.was_translocated,
    }


def import_tcc_grants(
    session: Session, grants: list[TCCGrantData], scan_id: str
) -> tuple[int, int]:
    """
    MERGE TCC_Permission nodes and HAS_TCC_GRANT relationships.
    Skips grants whose client bundle_id has no matching Application node.
    Returns (grants_linked, grants_skipped).
    """
    if not grants:
        return 0, 0

    records = _tcc_grant_records(grants, scan_id)
    _merge_tcc_permission_nodes(session, records)
    linked = _link_tcc_grants(session, records)
    skipped = len(records) - linked
    if skipped > 0:
        _record_unresolved_tcc_grants(session, records)
        logger.debug(
            "%d TCC grants had no matching Application node (path-only clients)",
            skipped,
        )
    return linked, skipped


def _tcc_grant_records(
    grants: list[TCCGrantData],
    scan_id: str,
) -> list[dict[str, object]]:
    return [
        {
            "service": g.service,
            "display_name": g.display_name,
            "client": g.client,
            "client_type": g.client_type,
            "allowed": g.allowed,
            "auth_reason": g.auth_reason_label,
            "auth_value": g.auth_value,
            "scope": g.scope,
            "last_modified": g.last_modified,
            "scan_id": scan_id,
            "grant_key": f"{scan_id}:{g.client}:{g.service}:{g.scope}",
        }
        for g in grants
    ]


def _merge_tcc_permission_nodes(
    session: Session,
    records: list[dict[str, object]],
) -> None:
    session.run(
        """
        UNWIND $records AS r
        MERGE (t:TCC_Permission {service: r.service})
        ON CREATE SET t.display_name = r.display_name
        """,
        records=records,
    )


def _link_tcc_grants(session: Session, records: list[dict[str, object]]) -> int:
    result = session.run(
        """
        UNWIND $records AS r
        MATCH (a:Application {scan_id: r.scan_id, bundle_id: r.client})
        MATCH (t:TCC_Permission {service: r.service})
        MERGE (a)-[rel:HAS_TCC_GRANT {scope: r.scope}]->(t)
        SET rel.allowed       = r.allowed,
            rel.auth_reason   = r.auth_reason,
            rel.auth_value    = r.auth_value,
            rel.client_type   = r.client_type,
            rel.last_modified = r.last_modified,
            rel.scan_id       = r.scan_id
        RETURN count(rel) AS linked
        """,
        records=records,
    )
    return result.single()["linked"]


def _record_unresolved_tcc_grants(
    session: Session,
    records: list[dict[str, object]],
) -> None:
    session.run(
        """
        UNWIND $records AS r
        OPTIONAL MATCH (a:Application {scan_id: r.scan_id, bundle_id: r.client})
        WITH r, a
        WHERE a IS NULL
        MATCH (t:TCC_Permission {service: r.service})
        MERGE (u:UnresolvedTCCGrant {grant_key: r.grant_key})
        SET u.service       = r.service,
            u.display_name  = r.display_name,
            u.client        = r.client,
            u.client_type   = r.client_type,
            u.allowed       = r.allowed,
            u.auth_reason   = r.auth_reason,
            u.auth_value    = r.auth_value,
            u.scope         = r.scope,
            u.last_modified = r.last_modified,
            u.scan_id       = r.scan_id,
            u.imported_at   = $imported_at
        MERGE (u)-[rel:REFERENCES_TCC_PERMISSION]->(t)
        SET rel.scan_id = r.scan_id
        """,
        records=records,
        imported_at=_now_iso(),
    )


def import_entitlements(
    session: Session, apps: list[ApplicationData], scan_id: str
) -> tuple[int, int]:
    """
    MERGE Entitlement nodes and HAS_ENTITLEMENT relationships.
    Returns (entitlement_nodes_created_or_merged, relationships_created_or_merged).
    """
    records = _entitlement_records(apps, scan_id)
    if not records:
        return 0, 0

    _merge_entitlement_nodes(session, records)
    rels = _link_entitlement_edges(session, records)
    unique_names = len({r["name"] for r in records})
    return unique_names, rels


def _entitlement_records(
    apps: list[ApplicationData],
    scan_id: str,
) -> list[dict[str, object]]:
    return [
        {
            "scan_id": scan_id,
            "bundle_id": app.bundle_id,
            "path": app.path,
            "name": ent.name,
            "is_private": ent.is_private,
            "category": ent.category,
            "is_security_critical": ent.is_security_critical,
        }
        for app in apps
        for ent in app.entitlements
    ]


def _merge_entitlement_nodes(
    session: Session,
    records: list[dict[str, object]],
) -> None:
    session.run(
        """
        UNWIND $records AS r
        MERGE (e:Entitlement {name: r.name})
        SET e.is_private          = r.is_private,
            e.category            = r.category,
            e.is_security_critical = r.is_security_critical
        """,
        records=records,
    )


def _link_entitlement_edges(
    session: Session,
    records: list[dict[str, object]],
) -> int:
    result = session.run(
        """
        UNWIND $records AS r
        MATCH (a:Application {scan_id: r.scan_id, bundle_id: r.bundle_id, path: r.path})
        MATCH (e:Entitlement {name: r.name})
        MERGE (a)-[rel:HAS_ENTITLEMENT]->(e)
        RETURN count(rel) AS rels
        """,
        records=records,
    )
    return result.single()["rels"]


def import_signed_by_team(session: Session) -> int:
    """
    Create SIGNED_BY_SAME_TEAM edges between all Application pairs sharing a team_id.
    Groups by team_id first to avoid an O(N^2) cross-join across all applications.
    Edges go from lexicographically smaller bundle_id to larger to avoid duplicates.
    Returns number of relationships created or merged.
    """
    result = session.run(
        """
        MATCH (a:Application)
        WHERE a.team_id IS NOT NULL
        WITH a.team_id AS tid, collect(a) AS apps
        WHERE size(apps) > 1
        UNWIND apps AS a
        UNWIND apps AS b
        WITH a, b WHERE a.bundle_id < b.bundle_id
        MERGE (a)-[r:SIGNED_BY_SAME_TEAM]->(b)
        SET r.team_id = a.team_id
        RETURN count(r) AS rels
        """
    )
    return result.single()["rels"]
