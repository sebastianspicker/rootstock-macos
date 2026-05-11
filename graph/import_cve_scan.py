#!/usr/bin/env python3
"""
import_cve_scan.py - Import a cve-scan Rootstock export into Neo4j.

The importer consumes the artifact produced by:

    cve-scan export-rootstock <run-dir>

It imports only the prebuilt JSON artifact. It does not call cve-scan internals
and does not require Neo4j during scanning.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from neo4j_connection import add_neo4j_args, connect_from_args


SUPPORTED_SCHEMA_VERSION = 7
IMPORT_SOURCE = "cve-scan"

CVE_SCAN_NODE_LABELS = {
    "Asset",
    "AssetContext",
    "Certificate",
    "CoverageGap",
    "DataContext",
    "Finding",
    "Host",
    "IdentityContext",
    "Manifest",
    "Owner",
    "Package",
    "Remediation",
    "Repository",
    "Service",
    "Vulnerability",
    "WebApp",
}

CVE_SCAN_EDGE_TYPES = {
    "AFFECTS",
    "CONTAINS_MANIFEST",
    "DECLARES_PACKAGE",
    "DEPENDS_ON",
    "EXPOSES",
    "HAS_CERT",
    "HAS_CONTEXT",
    "HAS_COVERAGE_GAP",
    "HAS_DATA_CONTEXT",
    "HAS_FINDING",
    "HAS_IDENTITY_CONTEXT",
    "HAS_REMEDIATION",
    "HOSTS",
    "MATCHED_BY",
    "OWNED_BY",
    "RUN",
    "SERVES",
}

_IDENTIFIER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


class CveScanImportError(ValueError):
    """Raised when a cve-scan export is not safe to import."""


@dataclass(frozen=True)
class CveScanExport:
    schema_version: int
    scope_name: str
    generated_at: str
    scan_profile: str
    node_types: frozenset[str]
    edge_vocabulary: frozenset[str]
    nodes: tuple[dict[str, object], ...]
    edges: tuple[dict[str, str], ...]


def load_export(path: Path) -> CveScanExport:
    """Load and validate a cve-scan Rootstock export from disk."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CveScanImportError(f"{path}: invalid JSON: {exc}") from exc
    return validate_export(raw)


def validate_export(raw: object) -> CveScanExport:
    """Validate export metadata, node labels, ids, and relationship types."""
    if not isinstance(raw, dict):
        raise CveScanImportError("export root must be a JSON object")

    schema_version = _required_int(raw, "schema_version")
    if schema_version != SUPPORTED_SCHEMA_VERSION:
        raise CveScanImportError(
            f"unsupported schema_version {schema_version}; expected {SUPPORTED_SCHEMA_VERSION}"
        )

    scope_name = _required_string(raw, "scope_name")
    generated_at = _required_string(raw, "generated_at")
    scan_profile = _required_string(raw, "scan_profile")
    node_types = frozenset(_required_string_list(raw, "node_types"))
    edge_vocabulary = frozenset(_required_string_list(raw, "edge_vocabulary"))
    edges_metadata = frozenset(_string_list(raw.get("edge_types"), "edge_types"))

    _validate_identifiers("node_types", node_types, CVE_SCAN_NODE_LABELS)
    _validate_identifiers("edge_vocabulary", edge_vocabulary, CVE_SCAN_EDGE_TYPES)
    if not edges_metadata.issubset(edge_vocabulary):
        unknown = ", ".join(sorted(edges_metadata - edge_vocabulary))
        raise CveScanImportError(f"edge_types not in edge_vocabulary: {unknown}")

    raw_nodes = raw.get("nodes")
    if not isinstance(raw_nodes, list):
        raise CveScanImportError("nodes must be a list")
    raw_edges = raw.get("edges")
    if not isinstance(raw_edges, list):
        raise CveScanImportError("edges must be a list")

    nodes: list[dict[str, object]] = []
    node_ids: set[str] = set()
    for index, raw_node in enumerate(raw_nodes):
        if not isinstance(raw_node, dict):
            raise CveScanImportError(f"nodes[{index}] must be an object")
        node_id = _node_id(raw_node, f"nodes[{index}]")
        label = _node_label(raw_node, f"nodes[{index}]")
        if label not in node_types:
            raise CveScanImportError(f"node {node_id!r} label {label!r} missing from node_types")
        if node_id in node_ids:
            raise CveScanImportError(f"duplicate node id: {node_id}")
        node_ids.add(node_id)
        nodes.append(dict(raw_node))

    edges: list[dict[str, str]] = []
    for index, raw_edge in enumerate(raw_edges):
        if not isinstance(raw_edge, dict):
            raise CveScanImportError(f"edges[{index}] must be an object")
        source_id = _edge_endpoint(raw_edge, "from", f"edges[{index}]")
        target_id = _edge_endpoint(raw_edge, "to", f"edges[{index}]")
        edge_type = _edge_type(raw_edge, f"edges[{index}]")
        if edge_type not in edge_vocabulary:
            raise CveScanImportError(
                f"edge {source_id!r}->{target_id!r} type {edge_type!r} missing from edge_vocabulary"
            )
        if source_id not in node_ids:
            raise CveScanImportError(f"edge source is not a known node id: {source_id}")
        if target_id not in node_ids:
            raise CveScanImportError(f"edge target is not a known node id: {target_id}")
        edges.append({"from": source_id, "to": target_id, "type": edge_type})

    return CveScanExport(
        schema_version=schema_version,
        scope_name=scope_name,
        generated_at=generated_at,
        scan_profile=scan_profile,
        node_types=node_types,
        edge_vocabulary=edge_vocabulary,
        nodes=tuple(nodes),
        edges=tuple(edges),
    )


def import_cve_scan_export(session, export: CveScanExport) -> dict[str, int]:
    """Import a validated cve-scan export into Neo4j and return import counts."""
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
        label = _node_label(node, "node")
        node_id = _node_id(node, "node")
        props = _neo4j_properties(node, export)
        cve_id = _extract_cve_id(node) if label == "Vulnerability" else None
        record = {"id": node_id, "props": props, "cve_id": cve_id}
        grouped.setdefault(label, []).append(record)
    return grouped


def build_edge_records(export: CveScanExport) -> dict[str, list[dict[str, str]]]:
    """Build grouped relationship MERGE records. Exposed for unit tests."""
    grouped: dict[str, list[dict[str, str]]] = {}
    for edge in export.edges:
        grouped.setdefault(edge["type"], []).append(
            {"source_id": edge["from"], "target_id": edge["to"]}
        )
    return grouped


def build_affected_by_alias_records(export: CveScanExport) -> list[dict[str, str]]:
    """Return asset -> vulnerability alias edge records derived from AFFECTS."""
    types_by_id = {_node_id(node, "node"): _node_label(node, "node") for node in export.nodes}
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
    if cve_records:
        result = session.run(
            """
            UNWIND $records AS row
            MERGE (n:Vulnerability {cve_id: row.cve_id})
            SET n += row.props
            RETURN count(n) AS n
            """,
            records=cve_records,
        )
        count += int(result.single()["n"])
    if other_records:
        result = session.run(
            """
            UNWIND $records AS row
            MERGE (n:Vulnerability {id: row.id})
            SET n += row.props
            RETURN count(n) AS n
            """,
            records=other_records,
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
        if key == "source":
            props["cve_scan_original_source"] = _neo4j_value(value)
            continue
        props[key] = _neo4j_value(value)

    props["source"] = IMPORT_SOURCE
    props["cve_scan_schema_version"] = export.schema_version
    props["cve_scan_scope_name"] = export.scope_name
    props["cve_scan_generated_at"] = export.generated_at
    props["cve_scan_profile"] = export.scan_profile

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
        if not isinstance(value, str):
            continue
        match = _CVE_RE.search(value)
        if match:
            return match.group(0).upper()
    return None


def _required_int(raw: dict[str, object], key: str) -> int:
    value = raw.get(key)
    if not isinstance(value, int):
        raise CveScanImportError(f"{key} must be an integer")
    return value


def _required_string(raw: dict[str, object], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str):
        raise CveScanImportError(f"{key} must be a string")
    return value


def _required_string_list(raw: dict[str, object], key: str) -> list[str]:
    return _string_list(raw.get(key), key, required=True)


def _string_list(value: object, key: str, *, required: bool = False) -> list[str]:
    if value is None and not required:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise CveScanImportError(f"{key} must be a list of strings")
    return value


def _validate_identifiers(name: str, values: frozenset[str], allowed: set[str]) -> None:
    invalid = sorted(value for value in values if not _IDENTIFIER_RE.fullmatch(value))
    if invalid:
        raise CveScanImportError(f"{name} contains unsafe identifiers: {', '.join(invalid)}")
    unknown = sorted(values - allowed)
    if unknown:
        raise CveScanImportError(f"{name} contains unsupported values: {', '.join(unknown)}")


def _node_id(node: dict[str, object], context: str) -> str:
    value = node.get("id")
    if not isinstance(value, str) or not value:
        raise CveScanImportError(f"{context}.id must be a non-empty string")
    return value


def _node_label(node: dict[str, object], context: str) -> str:
    value = node.get("type")
    if not isinstance(value, str) or not value:
        raise CveScanImportError(f"{context}.type must be a non-empty string")
    if not _IDENTIFIER_RE.fullmatch(value):
        raise CveScanImportError(f"{context}.type is not a safe Neo4j label: {value}")
    return value


def _edge_endpoint(edge: dict[str, object], key: str, context: str) -> str:
    value = edge.get(key)
    if not isinstance(value, str) or not value:
        raise CveScanImportError(f"{context}.{key} must be a non-empty string")
    return value


def _edge_type(edge: dict[str, object], context: str) -> str:
    value = edge.get("type")
    if not isinstance(value, str) or not value:
        raise CveScanImportError(f"{context}.type must be a non-empty string")
    if not _IDENTIFIER_RE.fullmatch(value):
        raise CveScanImportError(f"{context}.type is not a safe relationship type: {value}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Import a cve-scan rootstock-export.json artifact into Neo4j"
    )
    parser.add_argument("--input", required=True, help="Path to rootstock-export.json")
    add_neo4j_args(parser)
    args = parser.parse_args()

    try:
        export = load_export(Path(args.input))
    except CveScanImportError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    driver = connect_from_args(args)
    with driver.session() as session:
        counts = import_cve_scan_export(session, export)
    driver.close()

    print(
        "Imported cve-scan export "
        f"({counts['nodes']} nodes, {counts['edges']} relationships, "
        f"{counts['affected_by_aliases']} AFFECTED_BY aliases)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
