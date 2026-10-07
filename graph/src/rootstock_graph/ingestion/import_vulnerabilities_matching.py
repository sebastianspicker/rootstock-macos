"""Cypher-backed matching helpers for the two-tier AFFECTED_BY import."""

from __future__ import annotations

import logging

from ..category_predicates import VULNERABILITY_CATEGORY_PREDICATES
from ..vulnerability.cve_reference_models import CveEntry
from ..vulnerability.version_matcher import is_affected, parse_version_tuple, version_lte

logger = logging.getLogger(__name__)

_CATEGORY_MATCH = VULNERABILITY_CATEGORY_PREDICATES


def precise_match_records(session, cve: CveEntry) -> list[dict]:
    result = session.run(
        """
        MATCH (app:Application)
        WHERE app.bundle_id IN $bundle_ids
        OPTIONAL MATCH (app)-[:INSTALLED_ON]->(c:Computer)
        RETURN app.bundle_id AS bundle_id,
               app.version AS app_version,
               c.macos_version AS macos_version,
               elementId(app) AS app_id
        """,
        bundle_ids=list(cve.affected_bundle_ids),
    )
    return list(result)


def precise_record_is_affected(
    cve: CveEntry,
    record: dict,
    *,
    is_macos: bool,
) -> bool:
    app_version = record["app_version"]
    if cve.max_affected_version and app_version and not is_macos:
        try:
            app_v = parse_version_tuple(app_version)
            max_v = parse_version_tuple(cve.max_affected_version)
        except ValueError as exc:
            # Unparseable version: treat as unknown (conservatively affected)
            logger.warning(
                "Unparseable version for %s (%s): %s; treating version as unknown",
                record["bundle_id"],
                cve.cve_id,
                exc,
            )
            app_version = None
        else:
            return version_lte(app_v, max_v)

    return is_affected(
        app_version=app_version,
        affected_versions=cve.affected_versions,
        patched_version=cve.patched_version,
        is_macos_cve=is_macos,
        macos_version=record["macos_version"],
    )


def create_precise_affected_by_edge(session, *, app_id: str, cve_id: str) -> int:
    result = session.run(
        """
        MATCH (app:Application) WHERE elementId(app) = $app_id
        MATCH (v:Vulnerability {cve_id: $cve_id})
        MERGE (app)-[r:AFFECTED_BY]->(v)
        SET r.match_tier = 'precise'
        RETURN count(*) AS n
        """,
        app_id=app_id,
        cve_id=cve_id,
    )
    return result.single()["n"]


def category_fallback_cves(
    cves: list[CveEntry],
    precise_cve_ids: set[str],
) -> list[CveEntry]:
    return [cve for cve in cves if cve.cve_id not in precise_cve_ids]


def import_category_affected_by_edges(
    session,
    category: str,
    cves: list[CveEntry],
) -> int:
    match_clause = _CATEGORY_MATCH.get(category)
    if not match_clause:
        return 0

    cypher = f"""
        MATCH (app:Application)
        WHERE {match_clause}
        WITH app
        UNWIND $cve_ids AS cve_id
        MATCH (v:Vulnerability {{cve_id: cve_id}})
        MERGE (app)-[r:AFFECTED_BY]->(v)
        SET r.match_tier = 'category',
            r.match_source = 'category_fallback',
            r.match_confidence = 'heuristic',
            r.match_category = $category
        RETURN count(*) AS n
    """
    result = session.run(
        cypher,
        cve_ids=[cve.cve_id for cve in cves],
        category=category,
    )
    return result.single()["n"]
