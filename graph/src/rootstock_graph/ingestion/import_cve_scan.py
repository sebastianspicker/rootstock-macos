#!/usr/bin/env python3
"""
rootstock-graph-import-cve-scan - Import a cve-scan Rootstock export into Neo4j.

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

from jsonschema import Draft202012Validator, ValidationError

from ..neo4j import add_neo4j_args, connect_from_args
from .cve_scan_contract import load_schema_validator


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

CVE_SCAN_EXPORT_SCHEMA_ID = "https://rootstock.dev/contracts/cve-scan-export/v7/schema.json"

_IDENTIFIER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


class CveScanImportError(ValueError):
    """Raised when a cve-scan export is not safe to import."""


def _cve_scan_schema_validator() -> Draft202012Validator:
    return load_schema_validator(CVE_SCAN_EXPORT_SCHEMA_ID)


_CVE_SCAN_SCHEMA_VALIDATOR = _cve_scan_schema_validator()


@dataclass(frozen=True)
class CveScanExport:
    """Validated, immutable boundary object for a cve-scan graph export."""

    schema_version: int
    scope_name: str
    generated_at: str
    scan_profile: str
    node_types: frozenset[str]
    edge_vocabulary: frozenset[str]
    nodes: tuple[dict[str, object], ...]
    edges: tuple[dict[str, str], ...]


@dataclass(frozen=True)
class _ExportMetadata:
    schema_version: int
    scope_name: str
    generated_at: str
    scan_profile: str
    node_types: frozenset[str]
    edge_vocabulary: frozenset[str]


def load_export(path: Path) -> CveScanExport:
    """Load and validate a cve-scan Rootstock export from disk."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CveScanImportError(f"{path}: invalid JSON: {exc}") from exc
    return validate_export(raw)


def validate_export(raw: object) -> CveScanExport:
    """Validate export metadata, node labels, ids, and relationship types."""
    try:
        _CVE_SCAN_SCHEMA_VALIDATOR.validate(raw)
    except ValidationError as exc:
        raise CveScanImportError(f"schema validation failed: {exc.message}") from exc

    if not isinstance(raw, dict):
        raise CveScanImportError("export root must be a JSON object")

    metadata = _export_metadata(raw)

    raw_nodes = raw.get("nodes")
    if not isinstance(raw_nodes, list):
        raise CveScanImportError("nodes must be a list")
    raw_edges = raw.get("edges")
    if not isinstance(raw_edges, list):
        raise CveScanImportError("edges must be a list")

    nodes, node_ids = _validated_nodes(raw_nodes, metadata.node_types)
    edges = _validated_edges(raw_edges, metadata.edge_vocabulary, node_ids)
    _validate_semantic_metadata(raw, nodes, edges, metadata)

    return CveScanExport(
        schema_version=metadata.schema_version,
        scope_name=metadata.scope_name,
        generated_at=metadata.generated_at,
        scan_profile=metadata.scan_profile,
        node_types=metadata.node_types,
        edge_vocabulary=metadata.edge_vocabulary,
        nodes=tuple(nodes),
        edges=tuple(edges),
    )


def _export_metadata(raw: dict[object, object]) -> _ExportMetadata:
    """Validate schema and declared vocabularies before accepting payload records."""
    schema_version = _required_int(raw, "schema_version")
    if schema_version != SUPPORTED_SCHEMA_VERSION:
        raise CveScanImportError(
            f"unsupported schema_version {schema_version}; expected {SUPPORTED_SCHEMA_VERSION}"
        )

    node_types = frozenset(_required_string_list(raw, "node_types"))
    edge_vocabulary = frozenset(_required_string_list(raw, "edge_vocabulary"))

    _validate_identifiers("node_types", node_types, CVE_SCAN_NODE_LABELS)
    _validate_identifiers("edge_vocabulary", edge_vocabulary, CVE_SCAN_EDGE_TYPES)
    if edge_vocabulary != CVE_SCAN_EDGE_TYPES:
        raise CveScanImportError("edge_vocabulary must match the v7 contract vocabulary")

    return _ExportMetadata(
        schema_version=schema_version,
        scope_name=_required_string(raw, "scope_name"),
        generated_at=_required_string(raw, "generated_at"),
        scan_profile=_required_string(raw, "scan_profile"),
        node_types=node_types,
        edge_vocabulary=edge_vocabulary,
    )


def _validate_semantic_metadata(
    raw: dict[object, object],
    nodes: list[dict[str, object]],
    edges: list[dict[str, str]],
    metadata: _ExportMetadata,
) -> None:
    """Verify producer summaries describe exactly the validated graph records."""
    if _required_int(raw, "node_count") != len(nodes):
        raise CveScanImportError("node_count does not match nodes")
    if _required_int(raw, "edge_count") != len(edges):
        raise CveScanImportError("edge_count does not match edges")

    observed_node_types = frozenset(_node_label(node, "node") for node in nodes)
    if metadata.node_types != observed_node_types:
        raise CveScanImportError("node_types must exactly match the node type set")

    declared_edge_types = frozenset(_required_string_list(raw, "edge_types"))
    observed_edge_types = frozenset(edge["type"] for edge in edges)
    if declared_edge_types != observed_edge_types:
        raise CveScanImportError("edge_types must exactly match the edge type set")


def _validated_nodes(
    raw_nodes: list[object],
    node_types: frozenset[str],
) -> tuple[list[dict[str, object]], set[str]]:
    """Validate unique node identities and labels against the declared vocabulary."""
    nodes: list[dict[str, object]] = []
    node_ids: set[str] = set()
    for index, raw_node in enumerate(raw_nodes):
        if not isinstance(raw_node, dict):
            raise CveScanImportError(f"nodes[{index}] must be an object")
        node_id = _node_id(raw_node, f"nodes[{index}]")
        label = _node_label(raw_node, f"nodes[{index}]")
        if label not in node_types:
            raise CveScanImportError(f"node {node_id!r} label {label!r} missing from node_types")
        _append_unique_node(nodes, node_ids, raw_node, node_id)
    return nodes, node_ids


def _append_unique_node(
    nodes: list[dict[str, object]],
    node_ids: set[str],
    raw_node: dict[object, object],
    node_id: str,
) -> None:
    if node_id in node_ids:
        raise CveScanImportError(f"duplicate node id: {node_id}")
    node_ids.add(node_id)
    nodes.append(dict(raw_node))


def _validated_edges(
    raw_edges: list[object],
    edge_vocabulary: frozenset[str],
    node_ids: set[str],
) -> list[dict[str, str]]:
    """Validate relationships only after every referenced node ID is known."""
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
    return edges


def _required_int(raw: dict[object, object], key: str) -> int:
    value = raw.get(key)
    if not isinstance(value, int):
        raise CveScanImportError(f"{key} must be an integer")
    return value


def _required_string(raw: dict[object, object], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str):
        raise CveScanImportError(f"{key} must be a string")
    return value


def _required_string_list(raw: dict[object, object], key: str) -> list[str]:
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


def import_cve_scan_export(session, export: CveScanExport) -> dict[str, int]:
    """MERGE validated nodes before edges, making repeated imports idempotent."""
    from .cve_scan_neo4j import import_cve_scan_export as _import

    return _import(session, export)


def build_node_records(export: CveScanExport) -> dict[str, list[dict[str, object]]]:
    """Build grouped node MERGE records. Exposed for unit tests."""
    from .cve_scan_neo4j import build_node_records as _build

    return _build(export)


def build_edge_records(export: CveScanExport) -> dict[str, list[dict[str, str]]]:
    """Build grouped relationship MERGE records. Exposed for unit tests."""
    from .cve_scan_neo4j import build_edge_records as _build

    return _build(export)


def build_affected_by_alias_records(export: CveScanExport) -> list[dict[str, str]]:
    """Return asset -> vulnerability alias edge records derived from AFFECTS."""
    from .cve_scan_neo4j import build_affected_by_alias_records as _build

    return _build(export)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Import a cve-scan rootstock-export.json artifact into Neo4j"
    )
    parser.add_argument("--input", required=True, help="Path to rootstock-export.json")
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate the artifact without opening a Neo4j connection",
    )
    add_neo4j_args(parser)
    args = parser.parse_args()

    try:
        export = load_export(Path(args.input))
    except CveScanImportError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.validate_only:
        print(
            "Validated cve-scan export "
            f"({len(export.nodes)} nodes, {len(export.edges)} relationships)"
        )
        return 0

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
