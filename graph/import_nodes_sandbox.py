"""Sandbox profile node imports."""

from __future__ import annotations

from datetime import datetime, timezone

from neo4j import Session

from models import SandboxProfileData


def import_sandbox_profiles(
    session: Session, profiles: list[SandboxProfileData], scan_id: str
) -> tuple[int, int]:
    """
    MERGE SandboxProfile nodes and HAS_SANDBOX_PROFILE relationships.
    Returns (nodes_created, edges_created).
    """
    if not profiles:
        return 0, 0

    now = datetime.now(timezone.utc).isoformat()
    records = [_sandbox_profile_record(profile, scan_id, now) for profile in profiles]
    _merge_sandbox_profile_nodes(session, records)
    edges = _link_sandbox_profiles(session, records)
    return len(records), edges


def _sandbox_profile_record(
    profile: SandboxProfileData,
    scan_id: str,
    imported_at: str,
) -> dict[str, object]:
    return {
        "profile_key": f"{scan_id}:{profile.bundle_id}",
        "scan_id": scan_id,
        "bundle_id": profile.bundle_id,
        "profile_source": profile.profile_source,
        "file_read_rules": profile.file_read_rules,
        "file_write_rules": profile.file_write_rules,
        "mach_lookup_rules": profile.mach_lookup_rules,
        "network_rules": profile.network_rules,
        "iokit_rules": profile.iokit_rules,
        "exception_count": profile.exception_count,
        "has_unconstrained_network": profile.has_unconstrained_network,
        "has_unconstrained_file_read": profile.has_unconstrained_file_read,
        "imported_at": imported_at,
    }


def _merge_sandbox_profile_nodes(
    session: Session,
    records: list[dict[str, object]],
) -> None:
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


def _link_sandbox_profiles(
    session: Session,
    records: list[dict[str, object]],
) -> int:
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
    return result.single()["n"]
