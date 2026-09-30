"""Neo4j record construction and writes for validated cve-scan exports."""

from __future__ import annotations

import json
import re
from collections import defaultdict

from .cve_scan_contract import CveScanExport, IMPORT_SOURCE, require_node_id, require_node_label


_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def import_cve_scan_export(session, export: CveScanExport) -> dict[str, int]:
    """MERGE validated nodes before edges, making repeated imports idempotent."""
    node_counts = _import_nodes(session, export)
    edge_count = _import_edges(session, export)
    alias_count = _import_affected_by_aliases(session, export)
    return {
        "nodes": sum(node_counts.values()),
        "edges": edge_count,
        "affected_by_aliases": alias_count,
    }


def build_node_records(export: CveScanExport) -> dict[str, list[dict[str, object]]]:
    """Build grouped node MERGE records. Exposed for unit tests."""
    grouped: dict[str, list[dict[str, object]]] = {}
    for node in export.nodes:
        label = require_node_label(node, "node")
        node_id = require_node_id(node, "node")
        props = _neo4j_properties(node, export)
        cve_id = _extract_cve_id(node) if label == "Vulnerability" else None
        record = {"id": node_id, "props": props, "cve_id": cve_id}
        grouped.setdefault(label, []).append(record)
    return grouped


def build_edge_records(export: CveScanExport) -> dict[str, list[dict[str, str]]]:
    """Build grouped relationship MERGE records. Exposed for unit tests."""
    grouped: defaultdict[str, list[dict[str, str]]] = defaultdict(list)
    for edge in export.edges:
        grouped[edge["type"]].append({"source_id": edge["from"], "target_id": edge["to"]})
    return dict(grouped)


def build_affected_by_alias_records(export: CveScanExport) -> list[dict[str, str]]:
    """Return asset -> vulnerability alias edge records derived from AFFECTS."""
    types_by_id = {
        require_node_id(node, "node"): require_node_label(node, "node") for node in export.nodes
    }
    aliasable_assets = {"Host", "Package", "Service", "WebApp"}
    records = []
    for edge in export.edges:
        if edge["type"] != "AFFECTS":
            continue
        if types_by_id.get(edge["from"]) != "Vulnerability":
            continue
        if types_by_id.get(edge["to"]) not in aliasable_assets:
            continue
        records.append({"source_id": edge["to"], "target_id": edge["from"]})
    return records


def _import_nodes(session, export: CveScanExport) -> dict[str, int]:
    counts: dict[str, int] = {}
    for label, records in sorted(build_node_records(export).items()):
        if label == "Vulnerability":
            counts[label] = _import_vulnerability_nodes(session, records)
            continue
        result = session.run(
            f"""
            UNWIND $records AS row
            MERGE (n:{label} {{id: row.id}})
            SET n += row.props
            RETURN count(n) AS n
            """,
            records=records,
        )
        counts[label] = int(result.single()["n"])
    return counts


def _import_vulnerability_nodes(session, records: list[dict[str, object]]) -> int:
    cve_records = [record for record in records if record["cve_id"] is not None]
    other_records = [record for record in records if record["cve_id"] is None]
    count = 0
    for key, matching_records in (("cve_id", cve_records), ("id", other_records)):
        if not matching_records:
            continue
        result = session.run(
            f"""
            UNWIND $records AS row
            MERGE (n:Vulnerability {{{key}: row.{key}}})
            SET n += row.props
            RETURN count(n) AS n
            """,
            records=matching_records,
        )
        count += int(result.single()["n"])
    return count


def _import_edges(session, export: CveScanExport) -> int:
    count = 0
    for edge_type, records in sorted(build_edge_records(export).items()):
        result = session.run(
            f"""
            UNWIND $records AS row
            MATCH (source {{id: row.source_id}})
            MATCH (target {{id: row.target_id}})
            MERGE (source)-[r:{edge_type}]->(target)
            SET r.source = $source,
                r.cve_scan_scope_name = $scope_name,
                r.cve_scan_generated_at = $generated_at,
                r.cve_scan_profile = $scan_profile
            RETURN count(r) AS n
            """,
            records=records,
            source=IMPORT_SOURCE,
            scope_name=export.scope_name,
            generated_at=export.generated_at,
            scan_profile=export.scan_profile,
        )
        count += int(result.single()["n"])
    return count


def _import_affected_by_aliases(session, export: CveScanExport) -> int:
    records = build_affected_by_alias_records(export)
    if not records:
        return 0
    result = session.run(
        """
        UNWIND $records AS row
        MATCH (asset {id: row.source_id})
        MATCH (vulnerability:Vulnerability {id: row.target_id})
        MERGE (asset)-[r:AFFECTED_BY]->(vulnerability)
        SET r.source = $source,
            r.match_tier = 'cve-scan-export',
            r.cve_scan_scope_name = $scope_name,
            r.cve_scan_generated_at = $generated_at,
            r.cve_scan_profile = $scan_profile
        RETURN count(r) AS n
        """,
        records=records,
        source=IMPORT_SOURCE,
        scope_name=export.scope_name,
        generated_at=export.generated_at,
        scan_profile=export.scan_profile,
    )
    return int(result.single()["n"])


def _neo4j_properties(node: dict[str, object], export: CveScanExport) -> dict[str, object]:
    props: dict[str, object] = {}
    for key, value in node.items():
        props["cve_scan_original_source" if key == "source" else key] = _neo4j_value(value)
    props.update(
        {
            "source": IMPORT_SOURCE,
            "cve_scan_schema_version": export.schema_version,
            "cve_scan_scope_name": export.scope_name,
            "cve_scan_generated_at": export.generated_at,
            "cve_scan_profile": export.scan_profile,
        }
    )
    cve_id = _extract_cve_id(node)
    if cve_id is not None:
        props["cve_id"] = cve_id
    return props


def _neo4j_value(value: object) -> object:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list) and all(isinstance(item, (str, int, float, bool)) for item in value):
        return value
    return json.dumps(value, sort_keys=True)


def _extract_cve_id(node: dict[str, object]) -> str | None:
    for key in ("cve_id", "name", "id"):
        value = node.get(key)
        if isinstance(value, str) and (match := _CVE_RE.search(value)):
            return match.group(0).upper()
    return None
