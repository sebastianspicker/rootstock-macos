"""import_nodes_core.py — Core node imports (applications, TCC, entitlements, certificates)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from neo4j import Session

from models import (
    ApplicationData,
    TCCGrantData,
    ComputerData,
    SandboxProfileData,
)

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def import_computer(
    session: Session,
    computer: ComputerData,
    gatekeeper_enabled: bool | None = None,
    sip_enabled: bool | None = None,
    filevault_enabled: bool | None = None,
    lockdown_mode_enabled: bool | None = None,
    bluetooth_enabled: bool | None = None,
    bluetooth_discoverable: bool | None = None,
    screen_lock_enabled: bool | None = None,
    screen_lock_delay: int | None = None,
    display_sleep_timeout: int | None = None,
    thunderbolt_security_level: str | None = None,
    secure_boot_level: str | None = None,
    external_boot_allowed: bool | None = None,
    icloud_signed_in: bool | None = None,
    icloud_drive_enabled: bool | None = None,
    icloud_keychain_enabled: bool | None = None,
    collection_error_count: int = 0,
    collection_error_sources: list[str] | None = None,
) -> int:
    """MERGE a Computer node representing the scanned host. Returns 1."""
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
            c.collection_error_sources = $collection_error_sources
        """,
        computer_key=f"{computer.scan_id}:{computer.hostname}",
        hostname=computer.hostname,
        macos_version=computer.macos_version,
        scan_id=computer.scan_id,
        scanned_at=computer.scanned_at,
        collector_version=computer.collector_version,
        elevation_is_root=computer.elevation_is_root,
        elevation_has_fda=computer.elevation_has_fda,
        gatekeeper_enabled=gatekeeper_enabled,
        sip_enabled=sip_enabled,
        filevault_enabled=filevault_enabled,
        lockdown_mode_enabled=lockdown_mode_enabled,
        bluetooth_enabled=bluetooth_enabled,
        bluetooth_discoverable=bluetooth_discoverable,
        screen_lock_enabled=screen_lock_enabled,
        screen_lock_delay=screen_lock_delay,
        display_sleep_timeout=display_sleep_timeout,
        thunderbolt_security_level=thunderbolt_security_level,
        secure_boot_level=secure_boot_level,
        external_boot_allowed=external_boot_allowed,
        icloud_signed_in=icloud_signed_in,
        icloud_drive_enabled=icloud_drive_enabled,
        icloud_keychain_enabled=icloud_keychain_enabled,
        collection_error_count=collection_error_count,
        collection_error_sources=collection_error_sources or [],
    )
    return 1


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
    records = [
        {
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
            "is_sip_protected": app.is_sip_protected,
            "is_sandboxed": app.is_sandboxed,
            "sandbox_exceptions": app.sandbox_exceptions,
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
            "has_quarantine_flag": app.quarantine_info.has_quarantine_flag
            if app.quarantine_info
            else None,
            "quarantine_agent": app.quarantine_info.quarantine_agent
            if app.quarantine_info
            else None,
            "quarantine_timestamp": app.quarantine_info.quarantine_timestamp
            if app.quarantine_info
            else None,
            "was_user_approved": app.quarantine_info.was_user_approved
            if app.quarantine_info
            else None,
            "was_translocated": app.quarantine_info.was_translocated
            if app.quarantine_info
            else None,
            "scan_id": scan_id,
            "imported_at": now,
        }
        for app in apps
    ]

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
            a.is_sip_protected = r.is_sip_protected,
            a.is_sandboxed     = r.is_sandboxed,
            a.sandbox_exceptions = r.sandbox_exceptions,
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
    return len(records)


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

    records = [
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
        }
        for g in grants
    ]

    # MERGE the TCC_Permission nodes (they may already exist from the seed)
    session.run(
        """
        UNWIND $records AS r
        MERGE (t:TCC_Permission {service: r.service})
        ON CREATE SET t.display_name = r.display_name
        """,
        records=records,
    )

    # Create HAS_TCC_GRANT edges only where an Application node matches the client
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
    linked = result.single()["linked"]
    skipped = len(records) - linked
    if skipped > 0:
        logger.debug(
            "%d TCC grants had no matching Application node (path-only clients)",
            skipped,
        )
    return linked, skipped


def import_entitlements(
    session: Session, apps: list[ApplicationData], scan_id: str
) -> tuple[int, int]:
    """
    MERGE Entitlement nodes and HAS_ENTITLEMENT relationships.
    Returns (entitlement_nodes_created_or_merged, relationships_created_or_merged).
    """
    # Flatten app → entitlement pairs, keyed by bundle_id
    records = [
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

    if not records:
        return 0, 0

    # MERGE Entitlement nodes
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

    # MERGE HAS_ENTITLEMENT relationships
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
    rels = result.single()["rels"]

    # Count distinct entitlement names (nodes merged)
    unique_names = len({r["name"] for r in records})
    return unique_names, rels


def import_certificate_authorities(
    session: Session, apps: list[ApplicationData], scan_id: str
) -> tuple[int, int, int]:
    """
    Extract CertificateAuthority nodes from application certificate chains.
    Creates SIGNED_BY_CA (Application -> CA) and ISSUED_BY (CA -> CA) edges.
    Returns (ca_nodes, signed_by_ca_edges, issued_by_edges).
    """
    # Collect unique CAs by sha256 from all apps
    unique_cas: dict[str, dict] = {}
    for app in apps:
        for cert in app.certificate_chain:
            if cert.sha256 not in unique_cas:
                unique_cas[cert.sha256] = {
                    "sha256": cert.sha256,
                    "common_name": cert.common_name,
                    "organization": cert.organization,
                    "is_root": cert.is_root,
                    "valid_from": cert.valid_from,
                    "valid_to": cert.valid_to,
                }

    if not unique_cas:
        return 0, 0, 0

    # MERGE CertificateAuthority nodes
    ca_records = list(unique_cas.values())
    session.run(
        """
        UNWIND $records AS r
        MERGE (ca:CertificateAuthority {sha256: r.sha256})
        SET ca.common_name  = r.common_name,
            ca.organization = r.organization,
            ca.is_root      = r.is_root,
            ca.valid_from   = r.valid_from,
            ca.valid_to     = r.valid_to
        """,
        records=ca_records,
    )

    # SIGNED_BY_CA: Application -> leaf cert's CA (first in chain)
    signed_by_records = [
        {
            "scan_id": scan_id,
            "bundle_id": app.bundle_id,
            "path": app.path,
            "sha256": app.certificate_chain[0].sha256,
        }
        for app in apps
        if app.certificate_chain
    ]

    signed_by_count = 0
    if signed_by_records:
        result = session.run(
            """
            UNWIND $records AS r
            MATCH (a:Application {scan_id: r.scan_id, bundle_id: r.bundle_id, path: r.path})
            MATCH (ca:CertificateAuthority {sha256: r.sha256})
            MERGE (a)-[rel:SIGNED_BY_CA]->(ca)
            RETURN count(rel) AS n
            """,
            records=signed_by_records,
        )
        signed_by_count = result.single()["n"]

    # ISSUED_BY: consecutive pairs in each chain (chain[i] -> chain[i+1])
    issued_by_records = []
    for app in apps:
        chain = app.certificate_chain
        for i in range(len(chain) - 1):
            issued_by_records.append(
                {
                    "child_sha256": chain[i].sha256,
                    "parent_sha256": chain[i + 1].sha256,
                }
            )

    issued_by_count = 0
    if issued_by_records:
        result = session.run(
            """
            UNWIND $records AS r
            MATCH (child:CertificateAuthority {sha256: r.child_sha256})
            MATCH (parent:CertificateAuthority {sha256: r.parent_sha256})
            MERGE (child)-[rel:ISSUED_BY]->(parent)
            RETURN count(rel) AS n
            """,
            records=issued_by_records,
        )
        issued_by_count = result.single()["n"]

    return len(ca_records), signed_by_count, issued_by_count


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


def import_sandbox_profiles(
    session: Session, profiles: list[SandboxProfileData], scan_id: str
) -> tuple[int, int]:
    """
    MERGE SandboxProfile nodes and HAS_SANDBOX_PROFILE relationships.
    Returns (nodes_created, edges_created).
    """
    if not profiles:
        return 0, 0

    now = _now_iso()
    records = [
        {
            "profile_key": f"{scan_id}:{p.bundle_id}",
            "scan_id": scan_id,
            "bundle_id": p.bundle_id,
            "profile_source": p.profile_source,
            "file_read_rules": p.file_read_rules,
            "file_write_rules": p.file_write_rules,
            "mach_lookup_rules": p.mach_lookup_rules,
            "network_rules": p.network_rules,
            "iokit_rules": p.iokit_rules,
            "exception_count": p.exception_count,
            "has_unconstrained_network": p.has_unconstrained_network,
            "has_unconstrained_file_read": p.has_unconstrained_file_read,
            "imported_at": now,
        }
        for p in profiles
    ]

    # MERGE SandboxProfile nodes
    session.run(
        """
        UNWIND $records AS r
        MERGE (sp:SandboxProfile {profile_key: r.profile_key})
        SET sp.scan_id                  = r.scan_id,
            sp.bundle_id                = r.bundle_id,
            sp.profile_source           = r.profile_source,
            sp.file_read_rules          = r.file_read_rules,
            sp.file_write_rules         = r.file_write_rules,
            sp.mach_lookup_rules        = r.mach_lookup_rules,
            sp.network_rules            = r.network_rules,
            sp.iokit_rules              = r.iokit_rules,
            sp.exception_count          = r.exception_count,
            sp.has_unconstrained_network  = r.has_unconstrained_network,
            sp.has_unconstrained_file_read = r.has_unconstrained_file_read,
            sp.imported_at              = r.imported_at
        """,
        records=records,
    )

    # Create HAS_SANDBOX_PROFILE edges from Application to SandboxProfile
    result = session.run(
        """
        UNWIND $records AS r
        MATCH (a:Application {scan_id: r.scan_id, bundle_id: r.bundle_id})
        MATCH (sp:SandboxProfile {profile_key: r.profile_key})
        MERGE (a)-[rel:HAS_SANDBOX_PROFILE]->(sp)
        RETURN count(rel) AS n
        """,
        records=records,
    )
    edges = result.single()["n"]
    return len(records), edges
