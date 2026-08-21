#!/usr/bin/env python3
"""
import_vulnerabilities.py - Import Vulnerability and AttackTechnique nodes into Neo4j.

Reads the enriched CVE registry (static + cached EPSS/KEV/NVD data) and creates:
  - (:Vulnerability) nodes with EPSS, KEV, CVSS, CVSS vector properties
  - (:AttackTechnique) nodes with tactic/name
  - (:Vulnerability)-[:MAPS_TO_TECHNIQUE]->(:AttackTechnique) edges
  - (:Application)-[:AFFECTED_BY]->(:Vulnerability) edges via two-tier matching:
      Tier 1 (precise): bundle ID + version range match
      Tier 2 (category fallback): existing category-based heuristic matching

Usage:
    python3 graph/import_vulnerabilities.py [--neo4j bolt://localhost:7687]

Exit code 0 on success, 1 on failure.
"""

from __future__ import annotations

import argparse
import logging
import sys

from category_predicates import VULNERABILITY_CATEGORY_PREDICATES
from neo4j_connection import add_neo4j_args, connect_from_args
from cve_reference import (
    _REGISTRY,
    _GROUP_REGISTRY,
    _GROUP_TECHNIQUE_MAP,
    CveEntry,
    CWE_REGISTRY,
    REGISTRY_VERSION,
)
from cve_enrichment import enrich_registry, EnrichedCveEntry, temporal_score
from version_matcher import (
    extract_macos_max_version,
    is_affected,
    parse_version_tuple,
    version_lte,
)

logger = logging.getLogger(__name__)


_CATEGORY_MATCH = VULNERABILITY_CATEGORY_PREDICATES


# ── Import functions ─────────────────────────────────────────────────────


def _estimate_years_since_disclosure(entry: EnrichedCveEntry) -> float:
    """Estimate years since CVE disclosure from KEV date or patched_version hints."""
    from datetime import datetime, timezone

    # Try KEV date_added first (most reliable timestamp we have)
    if entry.kev_date_added:
        try:
            added = datetime.strptime(entry.kev_date_added, "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
            delta = datetime.now(timezone.utc) - added
            return max(0.0, delta.days / 365.25)
        except (ValueError, TypeError) as exc:
            logger.debug("Could not parse KEV date for %s: %s", entry.base.cve_id, exc)

    # Try extracting year from patched_version string (e.g. "macOS 15.2")
    # or from affected_versions (e.g. "macOS 15.1 and earlier")
    import re

    cve = entry.base
    year_match = re.search(r"CVE-(\d{4})-", cve.cve_id)
    if year_match:
        cve_year = int(year_match.group(1))
        current_year = datetime.now(timezone.utc).year
        return max(0.0, float(current_year - cve_year))

    # Default: assume 1 year old
    return 1.0


def _vulnerability_row(entry: EnrichedCveEntry) -> dict[str, object]:
    cve = entry.base
    years = _estimate_years_since_disclosure(entry)
    priority = temporal_score(cve.cvss_score, entry.epss_score, years)
    return {
        "cve_id": cve.cve_id,
        "title": cve.title,
        "cvss_score": cve.cvss_score,
        "epss_score": entry.epss_score,
        "epss_percentile": entry.epss_percentile,
        "in_kev": entry.in_kev,
        "kev_date_added": entry.kev_date_added,
        "exploitation_status": cve.exploitation_status,
        "attack_complexity": cve.attack_complexity,
        "affected_versions": cve.affected_versions,
        "patched_version": cve.patched_version,
        "description": cve.description,
        "reference_url": cve.reference_url,
        "kev_ransomware": entry.kev_ransomware,
        "cwe_ids": list(cve.cwe_ids),
        "cvss_vector": entry.cvss_vector,
        "temporal_priority": round(priority, 4),
    }


def import_vulnerability_nodes(session) -> int:
    """MERGE Vulnerability nodes from the enriched CVE registry (batched)."""
    enriched = enrich_registry()

    batch = [_vulnerability_row(entry) for entry in enriched.values()]

    if not batch:
        return 0

    result = session.run(
        """
        UNWIND $batch AS row
        MERGE (v:Vulnerability {cve_id: row.cve_id})
        SET v.title = row.title,
            v.cvss_score = row.cvss_score,
            v.epss_score = row.epss_score,
            v.epss_percentile = row.epss_percentile,
            v.in_kev = row.in_kev,
            v.kev_date_added = row.kev_date_added,
            v.exploitation_status = row.exploitation_status,
            v.attack_complexity = row.attack_complexity,
            v.affected_versions = row.affected_versions,
            v.patched_version = row.patched_version,
            v.description = row.description,
            v.reference_url = row.reference_url,
            v.kev_ransomware = row.kev_ransomware,
            v.cwe_ids = row.cwe_ids,
            v.cvss_vector = row.cvss_vector,
            v.temporal_priority = row.temporal_priority
        RETURN count(v) AS n
        """,
        batch=batch,
    )
    return result.single()["n"]


def import_technique_nodes(session) -> int:
    """MERGE AttackTechnique nodes from the registry (batched)."""
    seen: set[str] = set()
    batch = []

    for ctx in _REGISTRY.values():
        for tech in ctx.techniques:
            if tech.technique_id in seen:
                continue
            seen.add(tech.technique_id)
            batch.append(
                {
                    "technique_id": tech.technique_id,
                    "name": tech.name,
                    "tactic": tech.tactic,
                }
            )

    if not batch:
        return 0

    result = session.run(
        """
        UNWIND $batch AS row
        MERGE (t:AttackTechnique {technique_id: row.technique_id})
        SET t.name = row.name,
            t.tactic = row.tactic
        RETURN count(t) AS n
        """,
        batch=batch,
    )
    return result.single()["n"]


def import_technique_edges(session) -> int:
    """Create (:Vulnerability)-[:MAPS_TO_TECHNIQUE]->(:AttackTechnique) edges (batched)."""
    batch = []
    for ctx in _REGISTRY.values():
        for cve in ctx.cves:
            for tech in ctx.techniques:
                batch.append(
                    {
                        "cve_id": cve.cve_id,
                        "technique_id": tech.technique_id,
                    }
                )

    if not batch:
        return 0

    result = session.run(
        """
        UNWIND $batch AS row
        MATCH (v:Vulnerability {cve_id: row.cve_id})
        MATCH (t:AttackTechnique {technique_id: row.technique_id})
        MERGE (v)-[:MAPS_TO_TECHNIQUE]->(t)
        RETURN count(*) AS n
        """,
        batch=batch,
    )
    return result.single()["n"]


# ── Two-tier AFFECTED_BY matching ────────────────────────────────────────


def _has_macos_version_constraint(affected_versions: str) -> bool:
    """Check if the affected_versions string contains a macOS version pattern."""
    return extract_macos_max_version(affected_versions) is not None


def _collect_precise_cves() -> list[CveEntry]:
    """Return all CVEs that have affected_bundle_ids set (Tier 1 candidates)."""
    seen: set[str] = set()
    result: list[CveEntry] = []
    for ctx in _REGISTRY.values():
        for cve in ctx.cves:
            if cve.affected_bundle_ids and cve.cve_id not in seen:
                seen.add(cve.cve_id)
                result.append(cve)
    return result


def import_precise_affected_by_edges(session) -> tuple[int, int]:
    """Tier 1: Create AFFECTED_BY edges for CVEs with specific bundle ID targets.

    Matches Application nodes by bundle_id, then filters by version range
    using server-side version comparison where possible.
    """
    precise_cves = _collect_precise_cves()
    if not precise_cves:
        return 0, 0

    count = 0
    warning_count = 0
    for cve in precise_cves:
        cve_count, cve_warning_count = _import_precise_cve_affected_by_edges(
            session, cve
        )
        count += cve_count
        warning_count += cve_warning_count

    return count, warning_count


def _import_precise_cve_affected_by_edges(session, cve: CveEntry) -> tuple[int, int]:
    """Create precise AFFECTED_BY edges for one CVE and count its warnings."""
    try:
        records = _precise_match_records(session, cve)
    except Exception as e:
        print(f"  Warning: Precise match for {cve.cve_id} failed: {e}")
        return 0, 1

    count = 0
    warning_count = 0
    is_macos = _has_macos_version_constraint(cve.affected_versions)
    for record in records:
        if not _precise_record_is_affected(cve, record, is_macos=is_macos):
            continue
        try:
            count += _create_precise_affected_by_edge(
                session,
                app_id=record["app_id"],
                cve_id=cve.cve_id,
            )
        except Exception as e:
            warning_count += 1
            print(f"  Warning: Edge creation for {cve.cve_id} failed: {e}")

    return count, warning_count


def _precise_match_records(session, cve: CveEntry) -> list[dict]:
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


def _precise_record_is_affected(
    cve: CveEntry,
    record: dict,
    *,
    is_macos: bool,
) -> bool:
    app_version = record["app_version"]
    if cve.max_affected_version and app_version and not is_macos:
        app_v = parse_version_tuple(app_version)
        max_v = parse_version_tuple(cve.max_affected_version)
        return app_v is not None and max_v is not None and version_lte(app_v, max_v)

    return is_affected(
        app_version=app_version,
        affected_versions=cve.affected_versions,
        patched_version=cve.patched_version,
        is_macos_cve=is_macos,
        macos_version=record["macos_version"],
    )


def _create_precise_affected_by_edge(session, *, app_id: str, cve_id: str) -> int:
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


def import_affected_by_edges(session) -> tuple[int, int]:
    """Tier 2: Create AFFECTED_BY edges based on category matching (fallback).

    CVEs that already have Tier 1 (precise) edges are excluded from Tier 2
    to avoid duplicating edges for the same CVE with a weaker match tier.
    """
    # Collect CVE IDs already handled by Tier 1
    precise_cve_ids = {cve.cve_id for cve in _collect_precise_cves()}

    count = 0
    warning_count = 0

    for category, ctx in _REGISTRY.items():
        fallback_cves = _category_fallback_cves(ctx.cves, precise_cve_ids)
        if not fallback_cves:
            continue

        try:
            count += _import_category_affected_by_edges(session, category, fallback_cves)
        except Exception as e:
            warning_count += 1
            print(f"  Warning: AFFECTED_BY for category '{category}' failed: {e}")

    return count, warning_count


def _category_fallback_cves(
    cves: list[CveEntry],
    precise_cve_ids: set[str],
) -> list[CveEntry]:
    return [cve for cve in cves if cve.cve_id not in precise_cve_ids]


def _import_category_affected_by_edges(
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


def import_threat_group_nodes(session) -> int:
    """MERGE ThreatGroup nodes from the registry (batched)."""
    batch = [
        {"group_id": g.group_id, "name": g.name, "aliases": list(g.aliases)}
        for g in _GROUP_REGISTRY.values()
    ]
    if not batch:
        return 0

    result = session.run(
        """
        UNWIND $batch AS row
        MERGE (g:ThreatGroup {group_id: row.group_id})
        SET g.name = row.name,
            g.aliases = row.aliases
        RETURN count(g) AS n
        """,
        batch=batch,
    )
    return result.single()["n"]


def import_group_technique_edges(session) -> int:
    """Create (:ThreatGroup)-[:USES_TECHNIQUE]->(:AttackTechnique) edges (batched)."""
    batch = [
        {"gid": group_id, "tid": tid}
        for group_id, technique_ids in _GROUP_TECHNIQUE_MAP.items()
        for tid in technique_ids
    ]
    if not batch:
        return 0

    result = session.run(
        """
        UNWIND $batch AS row
        MATCH (g:ThreatGroup {group_id: row.gid})
        MATCH (t:AttackTechnique {technique_id: row.tid})
        MERGE (g)-[:USES_TECHNIQUE]->(t)
        RETURN count(*) AS n
        """,
        batch=batch,
    )
    return result.single()["n"]


def import_cwe_nodes(session) -> int:
    """MERGE CWE nodes from CWE_REGISTRY (batched)."""
    batch = [
        {"cwe_id": cwe.cwe_id, "name": cwe.name, "category": cwe.category}
        for cwe in CWE_REGISTRY.values()
    ]
    if not batch:
        return 0

    result = session.run(
        """
        UNWIND $batch AS row
        MERGE (c:CWE {cwe_id: row.cwe_id})
        SET c.name     = row.name,
            c.category = row.category
        RETURN count(c) AS n
        """,
        batch=batch,
    )
    return result.single()["n"]


def import_cwe_edges(session) -> int:
    """Create (:Vulnerability)-[:HAS_CWE]->(:CWE) edges from cwe_ids property."""
    result = session.run(
        """
        MATCH (v:Vulnerability)
        WHERE v.cwe_ids IS NOT NULL AND size(v.cwe_ids) > 0
        UNWIND v.cwe_ids AS cwe_id
        MATCH (c:CWE {cwe_id: cwe_id})
        MERGE (v)-[:HAS_CWE]->(c)
        RETURN count(*) AS n
        """
    )
    return result.single()["n"]


def import_all(session) -> dict[str, int]:
    """Run the full vulnerability import pipeline."""
    vuln_count = import_vulnerability_nodes(session)
    tech_count = import_technique_nodes(session)
    maps_count = import_technique_edges(session)
    precise_count, precise_warnings = import_precise_affected_by_edges(session)
    category_count, category_warnings = import_affected_by_edges(session)
    warning_count = precise_warnings + category_warnings
    group_count = import_threat_group_nodes(session)
    group_edge_count = import_group_technique_edges(session)
    cwe_count = import_cwe_nodes(session)
    cwe_edge_count = import_cwe_edges(session)

    return {
        "vulnerabilities": vuln_count,
        "techniques": tech_count,
        "maps_to_technique": maps_count,
        "affected_by_precise": precise_count,
        "affected_by_category": category_count,
        "affected_by": precise_count + category_count,
        "threat_groups": group_count,
        "uses_technique": group_edge_count,
        "cwe_nodes": cwe_count,
        "has_cwe_edges": cwe_edge_count,
        "warning_count": warning_count,
    }


# ── CLI ──────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Import Vulnerability and AttackTechnique nodes into Neo4j"
    )
    add_neo4j_args(parser)
    args = parser.parse_args()

    driver = connect_from_args(args)

    print(f"Importing vulnerability data (registry v{REGISTRY_VERSION})...")
    with driver.session() as session:
        counts = import_all(session)

    driver.close()

    print(f"  Vulnerability nodes: {counts['vulnerabilities']}")
    print(f"  AttackTechnique nodes: {counts['techniques']}")
    print(f"  MAPS_TO_TECHNIQUE edges: {counts['maps_to_technique']}")
    print(f"  AFFECTED_BY edges (precise): {counts['affected_by_precise']}")
    print(f"  AFFECTED_BY edges (category): {counts['affected_by_category']}")
    print(f"  AFFECTED_BY edges (total): {counts['affected_by']}")
    print(f"  ThreatGroup nodes: {counts['threat_groups']}")
    print(f"  USES_TECHNIQUE edges: {counts['uses_technique']}")
    print(f"  CWE nodes: {counts['cwe_nodes']}")
    print(f"  HAS_CWE edges: {counts['has_cwe_edges']}")
    if counts.get("warning_count", 0) > 0:
        print(
            f"  WARNING: {counts['warning_count']} vulnerability edge(s) failed; "
            "graph may be incomplete",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
