"""
import_installed_cves.py - Import NVD matches for installed software as AFFECTED_BY evidence.

Reads the installed-match cache written by ``rootstock-graph-cve-enrichment --fetch
--scan-json`` (offline; nothing is fetched here) and creates:

  - (:Vulnerability {source: 'nvd'}) nodes for matched CVEs not in the static registry
  - (:Application)-[:AFFECTED_BY {match_tier: 'cpe', match_source: 'nvd'}]->(:Vulnerability)
  - (:Computer)-[:AFFECTED_BY {match_tier: 'cpe', match_source: 'nvd'}]->(:Vulnerability)
    for the macOS release, plus macos_cve_count / macos_kev_cve_count / macos_cpe
  - (:CWE) nodes for CWE ids that the static CWE registry does not know

Static-registry nodes keep ``source = 'registry'`` and their curated properties.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from ..vulnerability.cve_enrichment import temporal_score
from ..vulnerability.nvd_installed import (
    MACOS_TARGET_ID,
    CpeMatchSet,
    CpeTarget,
    ExploitSignals,
    cached_installed_matches,
    enrich_installed_matches,
    matched_cve_ids,
    match_set_status,
    select_cpe_targets,
)
from ..vulnerability.nvd_installed_parse import NvdMatch, attack_complexity_from_vector
from .scan_loader import load_scan
from .installed_cve_coverage import import_cve_coverage

_MERGE_VULNERABILITIES = """
    UNWIND $rows AS row
    MERGE (v:Vulnerability {cve_id: row.cve_id})
    ON CREATE SET v.source = 'nvd'
    WITH v, row
    WHERE v.source = 'nvd'
    SET v += row.props
    RETURN count(v) AS n
"""

# NVD edges are rebuilt from the cache on every import, so drop the previous ones.
_DELETE_STALE_EDGES = (
    """
    MATCH (:Application {scan_id: $scan_id})-[r:AFFECTED_BY|HAS_CVE_CANDIDATE {match_source: 'nvd'}]->(:Vulnerability)
    DELETE r
    """,
    """
    MATCH (:Computer {scan_id: $scan_id})-[r:AFFECTED_BY|HAS_CVE_CANDIDATE {match_source: 'nvd'}]->(:Vulnerability)
    DELETE r
    """,
)

_SET_MATCH_EVIDENCE = """
    SET r.match_tier = 'cpe',
        r.match_source = 'nvd',
        r.cpe = row.cpe,
        r.matched_criteria = row.matched_criteria,
        r.match_confidence = row.applicability,
        r.required_conditions = row.required_conditions,
        r.fetched_at = row.fetched_at,
        r.cache_stale = row.stale,
        r.cache_complete = row.complete,
        r.cache_truncated = row.truncated,
        r.parser_version = row.parser_version
    RETURN count(r) AS n
"""

_MERGE_APP_EDGES = (
    """
    UNWIND $rows AS row
    MATCH (app:Application {scan_id: row.scan_id, bundle_id: row.bundle_id})
    WHERE app.version = row.app_version
    MATCH (v:Vulnerability {cve_id: row.cve_id})
    MERGE (app)-[r:AFFECTED_BY {match_source: 'nvd', cpe: row.cpe}]->(v)
"""
    + _SET_MATCH_EVIDENCE
)

_MERGE_HOST_EDGES = (
    """
    UNWIND $rows AS row
    MATCH (c:Computer {scan_id: row.scan_id})
    MATCH (v:Vulnerability {cve_id: row.cve_id})
    MERGE (c)-[r:AFFECTED_BY {match_source: 'nvd', cpe: row.cpe}]->(v)
"""
    + _SET_MATCH_EVIDENCE
)

_SET_HOST_SUMMARY = """
    MATCH (c:Computer {scan_id: $scan_id})
    OPTIONAL MATCH (c)-[:AFFECTED_BY {match_source: 'nvd'}]->(v:Vulnerability)
    WITH c, count(DISTINCT v) AS cves,
         count(DISTINCT CASE WHEN v.in_kev THEN v END) AS kev_cves
    SET c.macos_cve_count = cves,
        c.macos_kev_cve_count = kev_cves,
        c.macos_cpe = $cpe
    RETURN count(c) AS n
"""

_MERGE_CWE_NODES = """
    UNWIND $cwe_ids AS cwe_id
    MERGE (c:CWE {cwe_id: cwe_id})
    ON CREATE SET c.name = cwe_id
    RETURN count(c) AS n
"""


def _years_since(published: str | None) -> float:
    if not published:
        return 1.0
    try:
        then = datetime.fromisoformat(published)
    except ValueError:
        return 1.0
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    return max(0.0, (datetime.now(timezone.utc) - then).days / 365.25)


def vulnerability_props(match: NvdMatch, signals: ExploitSignals) -> dict[str, object]:
    """Vulnerability node properties for one NVD match."""
    priority = temporal_score(
        match.cvss_score or 0.0, signals.epss_score, _years_since(match.published)
    )
    return {
        "title": match.title,
        "description": match.description,
        "cvss_score": match.cvss_score,
        "cvss_vector": match.cvss_vector,
        "cvss_severity": match.cvss_severity,
        "epss_score": signals.epss_score,
        "epss_percentile": signals.epss_percentile,
        "in_kev": signals.in_kev,
        "kev_fetched_at": signals.kev_fetched_at,
        "kev_stale": signals.kev_stale,
        "epss_fetched_at": signals.epss_fetched_at,
        "epss_stale": signals.epss_stale,
        "kev_date_added": signals.kev_date_added,
        "kev_ransomware": signals.kev_ransomware,
        "published": match.published,
        "last_modified": match.last_modified,
        "reference_url": match.reference_url,
        "cwe_ids": list(match.cwe_ids),
        "temporal_priority": round(priority, 4),
        "exploitation_status": "actively_exploited" if signals.in_kev else "unknown",
        "attack_complexity": attack_complexity_from_vector(match.cvss_vector),
    }


def vulnerability_rows(match_sets: Iterable[CpeMatchSet]) -> list[dict[str, object]]:
    unique: dict[str, NvdMatch] = {}
    for match_set in match_sets:
        for match in match_set.matches:
            unique.setdefault(match.cve_id, match)
    signals = enrich_installed_matches(unique)
    return [
        {"cve_id": cve_id, "props": vulnerability_props(match, signals[cve_id])}
        for cve_id, match in sorted(unique.items())
    ]


def edge_rows(
    targets: Iterable[CpeTarget],
    match_sets: dict[str, CpeMatchSet],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Split edge rows into (application rows, host rows)."""
    app_rows: list[dict[str, object]] = []
    host_rows: list[dict[str, object]] = []
    for target in targets:
        match_set = match_sets.get(target.cpe_name)
        if match_set is None:
            continue
        rows = host_rows if target.bundle_id == MACOS_TARGET_ID else app_rows
        rows.extend(
            {
                "scan_id": target.scan_id,
                "bundle_id": target.bundle_id,
                "app_version": target.version,
                "cpe": target.cpe_name,
                "cve_id": match.cve_id,
                "matched_criteria": match.matched_criteria,
                "applicability": match.applicability,
                "required_conditions": list(match.required_conditions),
                **match_set_status(match_set),
            }
            for match in match_set.matches
        )
    return app_rows, host_rows


def _run_count(session, cypher: str, **params) -> int:
    record = session.run(cypher, **params).single()
    return int(record["n"] or 0) if record else 0


def _count_existing(session, cve_ids: list[str]) -> int:
    return _run_count(
        session,
        "MATCH (v:Vulnerability) WHERE v.cve_id IN $cve_ids RETURN count(v) AS n",
        cve_ids=cve_ids,
    )


def _import_host_summary(session, targets: list[CpeTarget], scan_id: str) -> None:
    cpe = next((target.cpe_name for target in targets if target.bundle_id == MACOS_TARGET_ID), None)
    _run_count(session, _SET_HOST_SUMMARY, scan_id=scan_id, cpe=cpe)


def _import_edges(session, cypher: str, rows: list[dict]) -> tuple[int, int]:
    verified, candidates = [], []
    for row in rows:
        confident = (
            row["applicability"] == "version_match"
            and not row["stale"]
            and not row["requires_refresh"]
        )
        (verified if confident else candidates).append(row)
    confirmed_count = _run_count(session, cypher, rows=verified) if verified else 0
    candidate_query = cypher.replace("r:AFFECTED_BY", "r:HAS_CVE_CANDIDATE")
    candidate_count = _run_count(session, candidate_query, rows=candidates) if candidates else 0
    return confirmed_count, candidate_count


def import_installed_matches(session, scan_path: Path) -> dict[str, object] | None:
    """Import cached NVD installed-software matches for one scan; None if it cannot load."""
    scan = load_scan(scan_path)
    if scan is None:
        return None
    selection = select_cpe_targets(scan)
    targets = list(selection.targets)
    found, missing = cached_installed_matches(targets)
    import_cve_coverage(session, scan, selection, found)
    rows = vulnerability_rows(found.values())
    cve_ids = matched_cve_ids(found.values())
    created = len(cve_ids) - _count_existing(session, cve_ids)
    if rows:
        _run_count(session, _MERGE_VULNERABILITIES, rows=rows)
    cwe_ids = sorted({cwe for row in rows for cwe in row["props"]["cwe_ids"]})
    if cwe_ids:
        _run_count(session, _MERGE_CWE_NODES, cwe_ids=cwe_ids)
    for cypher in _DELETE_STALE_EDGES:
        session.run(cypher, scan_id=scan.scan_id)
    app_rows, host_rows = edge_rows(targets, found)
    app_edges, app_candidates = _import_edges(session, _MERGE_APP_EDGES, app_rows)
    host_edges, host_candidates = _import_edges(session, _MERGE_HOST_EDGES, host_rows)
    _import_host_summary(session, targets, scan.scan_id)
    return {
        "targets": len(targets),
        "cached_targets": len(targets) - len(missing),
        "cve_nodes_created": created,
        "app_edges": app_edges,
        "host_edges": host_edges,
        "candidate_edges": app_candidates + host_candidates,
        "missing": missing,
    }
