#!/usr/bin/env python3
"""
import_family_export.py - Import a Rootstock family open-export into Neo4j.

Optional bridge (DD-011): rootstock-red / rootstock-blue produce versioned JSON
artifacts that are NOT full scan.json. Validation is fail-closed. Neo4j import
is optional when the driver/session is unavailable (validate-only mode).

Usage:
    python3 graph/import_family_export.py --export path.json --validate-only
    python3 graph/import_family_export.py --export path.json  # requires Neo4j
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

SUPPORTED_SCHEMA_VERSION = 1

FAMILY_SOURCES = frozenset({"rootstock-red", "rootstock-blue"})

FAMILY_NODE_LABELS = frozenset(
    {
        "Finding",
        "Host",
        "LaunchItem",
        "Protection",
    }
)

FAMILY_EDGE_TYPES = frozenset(
    {
        "HAS_FINDING",
        "HAS_LAUNCH_ITEM",
        "HAS_PROTECTION",
    }
)

_IDENTIFIER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


class FamilyExportError(ValueError):
    """Raised when a family open-export is not safe to import."""


@dataclass(frozen=True)
class FamilyExport:
    schema_version: int
    source: str
    generated_at: str
    scope_name: str
    scan_profile: str
    node_types: frozenset[str]
    edge_vocabulary: frozenset[str]
    nodes: tuple[dict[str, object], ...]
    edges: tuple[dict[str, str], ...]


def load_export(path: Path) -> FamilyExport:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise FamilyExportError(f"{path}: invalid JSON: {exc}") from exc
    return validate_export(raw)


def validate_export(raw: object) -> FamilyExport:
    if not isinstance(raw, dict):
        raise FamilyExportError("export root must be a JSON object")

    schema_version = _required_int(raw, "schema_version")
    if schema_version != SUPPORTED_SCHEMA_VERSION:
        raise FamilyExportError(
            f"unsupported schema_version {schema_version}; expected {SUPPORTED_SCHEMA_VERSION}"
        )

    source = _required_string(raw, "source")
    if source not in FAMILY_SOURCES:
        raise FamilyExportError(
            f"source must be one of {sorted(FAMILY_SOURCES)}; got {source!r}"
        )

    node_types = frozenset(_required_string_list(raw, "node_types"))
    edge_vocabulary = frozenset(_required_string_list(raw, "edge_vocabulary"))
    edge_types = frozenset(_string_list(raw.get("edge_types"), "edge_types"))

    _validate_identifiers("node_types", node_types, FAMILY_NODE_LABELS)
    _validate_identifiers("edge_vocabulary", edge_vocabulary, FAMILY_EDGE_TYPES)
    if not edge_types.issubset(edge_vocabulary):
        unknown = ", ".join(sorted(edge_types - edge_vocabulary))
        raise FamilyExportError(f"edge_types not in edge_vocabulary: {unknown}")

    raw_nodes = raw.get("nodes")
    if not isinstance(raw_nodes, list):
        raise FamilyExportError("nodes must be a list")
    raw_edges = raw.get("edges")
    if not isinstance(raw_edges, list):
        raise FamilyExportError("edges must be a list")

    nodes, node_ids = _validated_nodes(raw_nodes, node_types)
    edges = _validated_edges(raw_edges, edge_vocabulary, node_ids)

    return FamilyExport(
        schema_version=schema_version,
        source=source,
        generated_at=_required_string(raw, "generated_at"),
        scope_name=_required_string(raw, "scope_name"),
        scan_profile=_required_string(raw, "scan_profile"),
        node_types=node_types,
        edge_vocabulary=edge_vocabulary,
        nodes=tuple(nodes),
        edges=tuple(edges),
    )


def build_node_records(export: FamilyExport) -> dict[str, list[dict[str, object]]]:
    """Group nodes for MERGE by label. Exposed for unit tests."""
    grouped: dict[str, list[dict[str, object]]] = {}
    for node in export.nodes:
        label = str(node["type"])
        node_id = str(node["id"])
        props = {
            k: v
            for k, v in node.items()
            if k not in {"id", "type"} and _is_neo4j_safe(v)
        }
        props["id"] = node_id
        props["source"] = export.source
        props["family_export"] = True
        props["scope_name"] = export.scope_name
        grouped.setdefault(label, []).append({"id": node_id, "props": props})
    return grouped


def build_edge_records(export: FamilyExport) -> dict[str, list[dict[str, str]]]:
    grouped: dict[str, list[dict[str, str]]] = {}
    for edge in export.edges:
        grouped.setdefault(edge["type"], []).append(
            {"source_id": edge["from"], "target_id": edge["to"]}
        )
    return grouped


def import_family_export(session, export: FamilyExport) -> dict[str, int]:
    """MERGE validated family nodes/edges. Requires an open Neo4j session."""
    node_counts: dict[str, int] = {}
    for label, records in build_node_records(export).items():
        if not _IDENTIFIER_RE.match(label):
            raise FamilyExportError(f"unsafe node label: {label}")
        cypher = (
            f"UNWIND $batch AS row "
            f"MERGE (n:`{label}` {{id: row.id}}) "
            f"SET n += row.props"
        )
        session.run(cypher, batch=records)
        node_counts[label] = len(records)

    edge_count = 0
    for rel_type, records in build_edge_records(export).items():
        if not _IDENTIFIER_RE.match(rel_type):
            raise FamilyExportError(f"unsafe relationship type: {rel_type}")
        cypher = (
            f"UNWIND $batch AS row "
            f"MATCH (a {{id: row.source_id}}) "
            f"MATCH (b {{id: row.target_id}}) "
            f"MERGE (a)-[r:`{rel_type}`]->(b) "
            f"SET r.source = $source, r.family_export = true"
        )
        session.run(cypher, batch=records, source=export.source)
        edge_count += len(records)

    return {"nodes": sum(node_counts.values()), "edges": edge_count, **node_counts}


def _validated_nodes(
    raw_nodes: list[object],
    node_types: frozenset[str],
) -> tuple[list[dict[str, object]], set[str]]:
    nodes: list[dict[str, object]] = []
    node_ids: set[str] = set()
    for index, raw_node in enumerate(raw_nodes):
        if not isinstance(raw_node, dict):
            raise FamilyExportError(f"nodes[{index}] must be an object")
        node_id = _required_string(raw_node, "id")
        label = _required_string(raw_node, "type")
        if label not in node_types:
            raise FamilyExportError(
                f"node {node_id!r} type {label!r} missing from node_types"
            )
        if label not in FAMILY_NODE_LABELS:
            raise FamilyExportError(f"node label not allowlisted: {label}")
        if node_id in node_ids:
            raise FamilyExportError(f"duplicate node id: {node_id}")
        node_ids.add(node_id)
        nodes.append(dict(raw_node))
    return nodes, node_ids


def _validated_edges(
    raw_edges: list[object],
    edge_vocabulary: frozenset[str],
    node_ids: set[str],
) -> list[dict[str, str]]:
    edges: list[dict[str, str]] = []
    for index, raw_edge in enumerate(raw_edges):
        if not isinstance(raw_edge, dict):
            raise FamilyExportError(f"edges[{index}] must be an object")
        source_id = _required_string(raw_edge, "from")
        target_id = _required_string(raw_edge, "to")
        edge_type = _required_string(raw_edge, "type")
        if edge_type not in edge_vocabulary:
            raise FamilyExportError(
                f"edge type {edge_type!r} missing from edge_vocabulary"
            )
        if source_id not in node_ids:
            raise FamilyExportError(f"edge source is not a known node id: {source_id}")
        if target_id not in node_ids:
            raise FamilyExportError(f"edge target is not a known node id: {target_id}")
        edges.append({"from": source_id, "to": target_id, "type": edge_type})
    return edges


def _validate_identifiers(
    field: str, values: frozenset[str], allowlist: frozenset[str]
) -> None:
    unknown = values - allowlist
    if unknown:
        raise FamilyExportError(
            f"{field} contains non-allowlisted identifiers: {', '.join(sorted(unknown))}"
        )
    for value in values:
        if not _IDENTIFIER_RE.match(value):
            raise FamilyExportError(f"{field} has invalid identifier: {value!r}")


def _required_string(raw: dict[object, object], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise FamilyExportError(f"{key} must be a non-empty string")
    return value


def _required_int(raw: dict[object, object], key: str) -> int:
    value = raw.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise FamilyExportError(f"{key} must be an integer")
    return value


def _required_string_list(raw: dict[object, object], key: str) -> list[str]:
    value = raw.get(key)
    if not isinstance(value, list) or not value:
        raise FamilyExportError(f"{key} must be a non-empty list of strings")
    return _string_list(value, key)


def _string_list(value: object, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise FamilyExportError(f"{field} must be a list of strings")
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise FamilyExportError(f"{field} must contain non-empty strings")
        out.append(item)
    return out


def _is_neo4j_safe(value: object) -> bool:
    return isinstance(value, (str, int, float, bool)) or value is None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Import Rootstock family open-export")
    parser.add_argument("--export", required=True, type=Path, help="Path to family export JSON")
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate artifact only (no Neo4j connection)",
    )
    args = parser.parse_args(argv)

    try:
        export = load_export(args.export)
    except FamilyExportError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(
        f"OK: family export source={export.source} schema={export.schema_version} "
        f"nodes={len(export.nodes)} edges={len(export.edges)}"
    )

    if args.validate_only:
        # Touch builder paths so import packaging is exercised without Neo4j.
        node_groups = build_node_records(export)
        edge_groups = build_edge_records(export)
        print(
            f"validate-only node_labels={sorted(node_groups)} "
            f"edge_types={sorted(edge_groups)}"
        )
        return 0

    try:
        from neo4j_connection import add_neo4j_args, connect_from_args
    except ImportError as exc:
        print(f"ERROR: Neo4j helpers unavailable: {exc}", file=sys.stderr)
        return 1

    # Re-parse with neo4j args when not validate-only
    full = argparse.ArgumentParser(description="Import Rootstock family open-export")
    full.add_argument("--export", required=True, type=Path)
    full.add_argument("--validate-only", action="store_true")
    add_neo4j_args(full)
    full_args = full.parse_args(argv)
    driver = connect_from_args(full_args)
    try:
        with driver.session() as session:
            counts = import_family_export(session, export)
        print(f"imported {counts}")
    finally:
        driver.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
