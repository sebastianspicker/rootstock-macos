#!/usr/bin/env python3
"""Validate canonical cross-runtime contract schemas and deterministic fixtures.

Run with the graph environment so the repository uses its locked jsonschema
dependency:

    uv run --project graph --locked python scripts/check-contracts.py
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from rootstock_graph.ingestion import import_family_export
from rootstock_graph.paths import package_resource_dir


ROOT = Path(__file__).resolve().parent.parent
CONTRACTS = ROOT / "contracts"
FAMILY_PRODUCER_NODE_TYPES = ["Finding", "Host", "LaunchItem", "Protection"]
FAMILY_PRODUCER_EDGE_VOCABULARY = [
    "HAS_FINDING",
    "HAS_LAUNCH_ITEM",
    "HAS_PROTECTION",
]
SCHEMA_IDS = {
    "collector": "https://rootstock.dev/schema/scan-result.schema.json",
    "family": "https://rootstock.dev/contracts/family-open-export/v1/schema.json",
    "cve": "https://rootstock.dev/contracts/cve-scan-export/v7/schema.json",
    "red_finding": "https://rootstock.dev/contracts/red-findings-to-blue-jsonl/v1/red-finding.schema.json",
    "blue_input": "https://rootstock.dev/contracts/red-findings-to-blue-jsonl/v1/blue-import-input.schema.json",
}


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[object]:
    records: list[object] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise AssertionError(f"{path}:{line_number}: invalid JSONL: {exc}") from exc
    return records


def schema_errors(schema_path: Path, document: object) -> list[str]:
    schema = load_json(schema_path)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    return sorted(
        f"{'/'.join(map(str, error.absolute_path)) or '(root)'}: {error.message}"
        for error in validator.iter_errors(document)
    )


def assert_schema_identity(label: str, schema_path: Path, expected_id: str) -> None:
    schema = load_json(schema_path)
    actual_id = schema.get("$id") if isinstance(schema, dict) else None
    if actual_id != expected_id:
        raise AssertionError(
            f"{label} schema $id mismatch: expected {expected_id!r}, got {actual_id!r}"
        )
    print(f"OK schema identity: {label}")


def assert_packaged_family_schema_mirror(canonical_schema: Path) -> None:
    """Require the installed schema mirror to match canonical contract bytes exactly."""
    packaged_schema = package_resource_dir("contracts").joinpath(
        "family-open-export", "v1", "schema.json"
    )
    canonical_bytes = canonical_schema.read_bytes()
    packaged_bytes = packaged_schema.read_bytes()
    if packaged_bytes != canonical_bytes:
        raise AssertionError(
            "packaged family schema differs from canonical "
            f"{canonical_schema}; regenerate the read-only install mirror"
        )
    print("OK packaged family schema mirror")


def graph_invariants(document: object, *, require_counts: bool) -> list[str]:
    if not isinstance(document, dict):
        return ["root is not an object"]
    nodes = document.get("nodes")
    edges = document.get("edges")
    declared_nodes = document.get("node_types")
    declared_edges = document.get("edge_types")
    vocabulary = document.get("edge_vocabulary")
    if not all(
        isinstance(value, list)
        for value in (nodes, edges, declared_nodes, declared_edges, vocabulary)
    ):
        return ["graph arrays are missing or invalid"]

    errors: list[str] = []
    ids: list[str] = []
    node_types: set[str] = set()
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            continue
        node_id = node.get("id")
        node_type = node.get("type")
        if isinstance(node_id, str):
            ids.append(node_id)
        if isinstance(node_type, str):
            node_types.add(node_type)
            if node_type not in declared_nodes:
                errors.append(f"nodes[{index}] type {node_type!r} is not declared")
    if len(ids) != len(set(ids)):
        errors.append("node IDs must be unique")

    known_ids = set(ids)
    actual_edge_types: set[str] = set()
    for index, edge in enumerate(edges):
        if not isinstance(edge, dict):
            continue
        source, target, edge_type = edge.get("from"), edge.get("to"), edge.get("type")
        if isinstance(edge_type, str):
            actual_edge_types.add(edge_type)
            if edge_type not in vocabulary:
                errors.append(
                    f"edges[{index}] type {edge_type!r} is not in edge_vocabulary"
                )
        if isinstance(source, str) and source not in known_ids:
            errors.append(f"edges[{index}] source {source!r} is not a node ID")
        if isinstance(target, str) and target not in known_ids:
            errors.append(f"edges[{index}] target {target!r} is not a node ID")

    if declared_edges != sorted(actual_edge_types):
        errors.append("edge_types must equal the sorted set of emitted edge types")
    if require_counts:
        if document.get("node_count") != len(nodes):
            errors.append("node_count must equal nodes length")
        if document.get("edge_count") != len(edges):
            errors.append("edge_count must equal edges length")
        if declared_nodes != sorted(node_types):
            errors.append("node_types must equal the sorted set of emitted node types")
    return errors


def family_runtime_errors(document: object) -> list[str]:
    try:
        import_family_export.validate_export(document)
    except import_family_export.FamilyExportError as exc:
        return [str(exc)]
    return []


def family_producer_output_errors(document: object) -> list[str]:
    """Check fixture parity with the current Red and Blue producer implementations."""
    if not isinstance(document, dict):
        return ["producer fixture root is not an object"]
    source = document.get("source")
    nodes = document.get("nodes")
    edges = document.get("edges")
    errors: list[str] = []
    if document.get("node_types") != FAMILY_PRODUCER_NODE_TYPES:
        errors.append("producer node_types must be the current fixed vocabulary")
    if document.get("edge_vocabulary") != FAMILY_PRODUCER_EDGE_VOCABULARY:
        errors.append("producer edge_vocabulary must be the current fixed vocabulary")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        return errors + ["producer fixture nodes and edges must be arrays"]
    if not nodes or not isinstance(nodes[0], dict) or nodes[0].get("type") != "Host":
        errors.append("producer output must begin with its Host node")
    else:
        required_host_keys = {"id", "type", "name", "hostname"}
        if source == "rootstock-red":
            required_host_keys.add("os_version")
        elif source == "rootstock-blue":
            required_host_keys.add("case_name")
        else:
            errors.append(f"unknown producer source {source!r}")
        if not required_host_keys.issubset(nodes[0]):
            errors.append("producer Host node is missing its emitted fields")
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            continue
        node_type = node.get("type")
        required_keys = {
            "Finding": {"id", "type", "name", "finding_id", "severity", "category"},
            "LaunchItem": {"id", "type", "name", "label", "path", "program"},
            "Protection": {"id", "type", "name", "enabled"},
        }.get(node_type, set())
        if source == "rootstock-red" and node_type == "Finding":
            required_keys = required_keys | {"confidence"}
        if not required_keys.issubset(node):
            errors.append(
                f"producer node {index} is missing emitted {node_type} fields"
            )
    actual_edge_types = sorted(
        edge["type"]
        for edge in edges
        if isinstance(edge, dict) and isinstance(edge.get("type"), str)
    )
    if document.get("edge_types") != sorted(set(actual_edge_types)):
        errors.append(
            "producer edge_types must be the sorted set of emitted edge types"
        )
    return errors


def cve_graph_invariants(document: object) -> list[str]:
    return graph_invariants(document, require_counts=True)


def assert_valid(
    label: str,
    schema_path: Path,
    document: object,
    invariants: Callable[[object], list[str]] | None = None,
) -> None:
    errors = schema_errors(schema_path, document)
    if invariants is not None:
        errors.extend(invariants(document))
    if errors:
        raise AssertionError(f"{label} should be valid:\n  " + "\n  ".join(errors))
    print(f"OK valid: {label}")


def assert_invalid(
    label: str,
    schema_path: Path,
    document: object,
    invariants: Callable[[object], list[str]] | None = None,
) -> None:
    errors = schema_errors(schema_path, document)
    if invariants is not None:
        errors.extend(invariants(document))
    if not errors:
        raise AssertionError(f"{label} should be invalid")
    print(f"OK invalid: {label}")


def assert_family_runtime_valid(
    label: str,
    schema_path: Path,
    document: object,
    *,
    producer_parity: bool = False,
) -> None:
    errors = schema_errors(schema_path, document) + family_runtime_errors(document)
    if producer_parity:
        errors.extend(family_producer_output_errors(document))
    if errors:
        raise AssertionError(f"{label} should be accepted:\n  " + "\n  ".join(errors))
    print(f"OK accepted: {label}")


def assert_family_runtime_invalid(
    label: str,
    schema_path: Path,
    document: object,
    *,
    require_schema_rejection: bool = False,
) -> None:
    errors = family_runtime_errors(document)
    if not errors:
        raise AssertionError(f"{label} should be rejected by the live importer")
    if require_schema_rejection and not schema_errors(schema_path, document):
        raise AssertionError(f"{label} should be rejected by the canonical schema")
    print(f"OK rejected: {label}")


def main() -> int:
    collector_schema = CONTRACTS / "collector-scan" / "legacy-unversioned.schema.json"
    family_schema = CONTRACTS / "family-open-export" / "v1" / "schema.json"
    cve_schema = CONTRACTS / "cve-scan-export" / "v7" / "schema.json"
    red_schema = (
        CONTRACTS / "red-findings-to-blue-jsonl" / "v1" / "red-finding.schema.json"
    )
    blue_input_schema = (
        CONTRACTS
        / "red-findings-to-blue-jsonl"
        / "v1"
        / "blue-import-input.schema.json"
    )

    try:
        assert_schema_identity("collector", collector_schema, SCHEMA_IDS["collector"])
        assert_schema_identity("family", family_schema, SCHEMA_IDS["family"])
        assert_packaged_family_schema_mirror(family_schema)
        assert_schema_identity("cve-scan", cve_schema, SCHEMA_IDS["cve"])
        assert_schema_identity("red finding", red_schema, SCHEMA_IDS["red_finding"])
        assert_schema_identity(
            "Blue JSONL input", blue_input_schema, SCHEMA_IDS["blue_input"]
        )

        assert_valid(
            "collector minimal fixture",
            collector_schema,
            load_json(CONTRACTS / "collector-scan" / "fixtures" / "valid-minimal.json"),
        )
        assert_valid(
            "collector public example",
            collector_schema,
            load_json(ROOT / "examples" / "demo-scan.json"),
        )
        assert_valid(
            "collector family collision fixture",
            collector_schema,
            load_json(
                CONTRACTS
                / "collector-scan"
                / "fixtures"
                / "valid-family-collision-launch-items.json"
            ),
        )
        assert_invalid(
            "collector missing required fixture",
            collector_schema,
            load_json(
                CONTRACTS
                / "collector-scan"
                / "fixtures"
                / "invalid-missing-required.json"
            ),
        )

        assert_family_runtime_valid(
            "family v1 minimal Red fixture",
            family_schema,
            load_json(
                CONTRACTS
                / "family-open-export"
                / "v1"
                / "fixtures"
                / "valid-minimal-red.json"
            ),
            producer_parity=True,
        )
        for fixture in ("family-export-red.json", "family-export-blue.json"):
            assert_family_runtime_valid(
                f"family v1 public {fixture}",
                family_schema,
                load_json(ROOT / "examples" / fixture),
                producer_parity=True,
            )
        assert_family_runtime_valid(
            "family v1 importer-compatible extension fixture",
            family_schema,
            load_json(
                CONTRACTS
                / "family-open-export"
                / "v1"
                / "fixtures"
                / "valid-importer-minimal.json"
            ),
        )
        assert_family_runtime_invalid(
            "family v1 dangling edge fixture",
            family_schema,
            load_json(
                CONTRACTS
                / "family-open-export"
                / "v1"
                / "fixtures"
                / "invalid-dangling-edge.json"
            ),
        )
        assert_family_runtime_invalid(
            "family v1 undeclared node label fixture",
            family_schema,
            load_json(
                CONTRACTS
                / "family-open-export"
                / "v1"
                / "fixtures"
                / "invalid-undeclared-node-label.json"
            ),
        )
        assert_family_runtime_invalid(
            "family v1 unknown node type fixture",
            family_schema,
            load_json(
                CONTRACTS
                / "family-open-export"
                / "v1"
                / "fixtures"
                / "invalid-unknown-node-type.json"
            ),
            require_schema_rejection=True,
        )

        assert_valid(
            "cve-scan v7 minimal fixture",
            cve_schema,
            load_json(
                CONTRACTS / "cve-scan-export" / "v7" / "fixtures" / "valid-minimal.json"
            ),
            cve_graph_invariants,
        )
        assert_valid(
            "cve-scan v7 public example",
            cve_schema,
            load_json(ROOT / "examples" / "cve-scan-export.json"),
            cve_graph_invariants,
        )
        assert_invalid(
            "cve-scan v7 count mismatch fixture",
            cve_schema,
            load_json(
                CONTRACTS / "cve-scan-export" / "v7" / "fixtures" / "invalid-count.json"
            ),
            cve_graph_invariants,
        )

        valid_red_records = load_jsonl(
            CONTRACTS / "red-findings-to-blue-jsonl" / "v1" / "fixtures" / "valid.jsonl"
        )
        for index, record in enumerate(valid_red_records):
            assert_valid(f"red finding JSONL record {index}", red_schema, record)
            assert_valid(
                f"blue accepted JSONL record {index}", blue_input_schema, record
            )
        for index, record in enumerate(
            load_jsonl(
                CONTRACTS
                / "red-findings-to-blue-jsonl"
                / "v1"
                / "fixtures"
                / "invalid-producer-severity.jsonl"
            )
        ):
            assert_invalid(f"red invalid severity record {index}", red_schema, record)
        for index, record in enumerate(
            load_jsonl(
                CONTRACTS
                / "red-findings-to-blue-jsonl"
                / "v1"
                / "fixtures"
                / "invalid-blue-input.jsonl"
            )
        ):
            assert_invalid(
                f"blue non-object input record {index}", blue_input_schema, record
            )
    except (AssertionError, OSError, json.JSONDecodeError) as exc:
        print(f"CONTRACT CHECK FAILED: {exc}", file=sys.stderr)
        return 1

    print("Contract checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
