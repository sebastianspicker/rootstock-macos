"""TCC and entitlement Neo4j imports for collector application data."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from neo4j import Session

from ..models import ApplicationData, TCCGrantData

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def import_tcc_grants(
    session: Session, grants: list[TCCGrantData], scan_id: str
) -> tuple[int, int]:
    """MERGE TCC data and return linked and unresolved grant counts."""
    if not grants:
        return 0, 0
    records = _tcc_grant_records(grants, scan_id)
    _merge_tcc_permission_nodes(session, records)
    linked = _link_tcc_grants(session, records)
    skipped = len(records) - linked
    if skipped > 0:
        _record_unresolved_tcc_grants(session, records)
        logger.debug("%d TCC grants had no matching Application node (path-only clients)", skipped)
    return linked, skipped


def _tcc_grant_records(grants: list[TCCGrantData], scan_id: str) -> list[dict[str, object]]:
    return [
        {
            "service": grant.service,
            "display_name": grant.display_name,
            "client": grant.client,
            "client_type": grant.client_type,
            "allowed": grant.allowed,
            "auth_reason": grant.auth_reason_label,
            "auth_value": grant.auth_value,
            "scope": grant.scope,
            "last_modified": grant.last_modified,
            "scan_id": scan_id,
            "grant_key": f"{scan_id}:{grant.client}:{grant.service}:{grant.scope}",
        }
        for grant in grants
    ]


def _merge_tcc_permission_nodes(session: Session, records: list[dict[str, object]]) -> None:
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


def _record_unresolved_tcc_grants(session: Session, records: list[dict[str, object]]) -> None:
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
    """MERGE entitlement nodes and application relationships."""
    records = _entitlement_records(apps, scan_id)
    if not records:
        return 0, 0
    _merge_entitlement_nodes(session, records)
    relationships = _link_entitlement_edges(session, records)
    return len({record["name"] for record in records}), relationships


def _entitlement_records(apps: list[ApplicationData], scan_id: str) -> list[dict[str, object]]:
    return [
        {
            "scan_id": scan_id,
            "bundle_id": app.bundle_id,
            "path": app.path,
            "name": entitlement.name,
            "is_private": entitlement.is_private,
            "category": entitlement.category,
            "is_security_critical": entitlement.is_security_critical,
        }
        for app in apps
        for entitlement in app.entitlements
    ]


def _merge_entitlement_nodes(session: Session, records: list[dict[str, object]]) -> None:
    session.run(
        """
        UNWIND $records AS r
        MERGE (e:Entitlement {name: r.name})
        SET e.is_private           = r.is_private,
            e.category             = r.category,
            e.is_security_critical = r.is_security_critical
        """,
        records=records,
    )


def _link_entitlement_edges(session: Session, records: list[dict[str, object]]) -> int:
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
