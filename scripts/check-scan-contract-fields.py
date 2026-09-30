#!/usr/bin/env python3
"""Check the collector scan schema's fields against its producer and consumer.

Source of truth:
contracts/collector-scan/legacy-unversioned.schema.json

Producer: contracts/collector-scan/fixtures/valid-collector-encoder-complete.json
is the collector's real JSONExporter output (kept equal by the Swift test
CompleteScanFixtureTests; schema validity is checked by
scripts/check-contracts.py). It must exercise every property declared anywhere
in the schema, apart from the documented properties the encoder never writes.
The closed schema already rejects properties the encoder emits but the schema
does not declare.

Consumer: top-level keys must match rootstock_graph.models.ScanResult field
aliases (Pydantic), and the graph model must accept the complete encoder
fixture, so nested drift on the consumer side is caught too.

Run with the graph environment so rootstock_graph is installed:

    uv run --project graph --locked python scripts/check-scan-contract-fields.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from rootstock_graph import models

ROOT = Path(__file__).resolve().parent.parent
SCAN_CONTRACT = ROOT / "contracts" / "collector-scan"
SCHEMA_PATH = SCAN_CONTRACT / "legacy-unversioned.schema.json"
ENCODER_FIXTURE_PATH = SCAN_CONTRACT / "fixtures" / "valid-collector-encoder-complete.json"
# Schema properties that consumers accept but the Swift encoder never writes.
PROPERTIES_NOT_EMITTED = {"KeychainItem.sensitivity"}


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def load_schema_keys(schema: dict) -> tuple[set[str], set[str]]:
    props = set(schema.get("properties", {}).keys())
    required = set(schema.get("required", []))
    return props, required


def load_pydantic_keys() -> set[str]:
    models.ScanResult.model_rebuild(_types_namespace=vars(models))
    # model_fields keys are Python names; serialization aliases may differ
    keys: set[str] = set()
    for name, field in models.ScanResult.model_fields.items():
        alias = field.alias or field.serialization_alias or name
        keys.add(str(alias))
    return keys


def _pydantic_alignment_errors(schema_keys: set[str], required: set[str]) -> list[str]:
    errors: list[str] = []
    pydantic_keys = load_pydantic_keys()

    only_schema = sorted(schema_keys - pydantic_keys)
    only_pydantic = sorted(pydantic_keys - schema_keys)
    if only_schema:
        errors.append(f"in schema but not Pydantic ScanResult: {only_schema}")
    if only_pydantic:
        errors.append(f"in Pydantic ScanResult but not schema: {only_pydantic}")

    missing_req = sorted(required - pydantic_keys)
    if missing_req:
        errors.append(f"required schema fields missing on Pydantic: {missing_req}")

    return errors


def declared_properties(schema: dict) -> set[str]:
    """Every object property in the schema as ``Owner.property``."""
    declared = {f"root.{key}" for key in schema.get("properties", {})}
    for def_name, definition in schema.get("$defs", {}).items():
        declared.update(f"{def_name}.{key}" for key in definition.get("properties", {}))
    return declared


def _collect_emitted(
    schema: dict, node: dict, owner: str, value: object, emitted: set[str]
) -> None:
    ref = node.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/$defs/"):
        owner = ref.removeprefix("#/$defs/")
        node = schema["$defs"][owner]
    for branch in node.get("oneOf", []):
        if value is not None and branch.get("type") != "null":
            _collect_emitted(schema, branch, owner, value, emitted)
    _collect_children(schema, node, owner, value, emitted)


def _collect_children(
    schema: dict, node: dict, owner: str, value: object, emitted: set[str]
) -> None:
    properties = node.get("properties", {})
    if isinstance(value, dict):
        for key, child in value.items():
            if key in properties:
                emitted.add(f"{owner}.{key}")
                _collect_emitted(schema, properties[key], owner, child, emitted)
    elif isinstance(value, list) and isinstance(node.get("items"), dict):
        for item in value:
            _collect_emitted(schema, node["items"], owner, item, emitted)


def _encoder_coverage_errors(schema: dict, fixture: object) -> tuple[list[str], str]:
    declared = declared_properties(schema)
    emitted: set[str] = set()
    _collect_emitted(schema, schema, "root", fixture, emitted)

    errors: list[str] = []
    missing = sorted(declared - emitted - PROPERTIES_NOT_EMITTED)
    if missing:
        errors.append(f"schema properties the encoder fixture never emits: {missing}")
    stale = sorted(PROPERTIES_NOT_EMITTED & emitted)
    if stale:
        errors.append(f"listed as not emitted but present in encoder fixture: {stale}")
    unknown = sorted(PROPERTIES_NOT_EMITTED - declared)
    if unknown:
        errors.append(f"listed as not emitted but not declared in schema: {unknown}")
    summary = (
        f"encoder fixture covers {len(emitted)}/{len(declared)} schema properties "
        f"(not emitted: {sorted(PROPERTIES_NOT_EMITTED)})"
    )
    return errors, summary


def main() -> int:
    for path in (SCHEMA_PATH, ENCODER_FIXTURE_PATH):
        if not path.is_file():
            print(f"ERROR: missing {path}", file=sys.stderr)
            return 1

    schema = load_json(SCHEMA_PATH)
    if not isinstance(schema, dict):
        print(f"ERROR: {SCHEMA_PATH} root is not an object", file=sys.stderr)
        return 1
    schema_keys, required = load_schema_keys(schema)
    errors = _pydantic_alignment_errors(schema_keys, required)
    coverage_errors, coverage = _encoder_coverage_errors(schema, load_json(ENCODER_FIXTURE_PATH))
    errors.extend(coverage_errors)
    try:
        models.ScanResult.model_validate(load_json(ENCODER_FIXTURE_PATH))
    except ValueError as exc:
        errors.append(f"graph ScanResult rejects the encoder fixture: {exc}")

    if errors:
        print("Scan contract field check FAILED:")
        for e in errors:
            print(f"  - {e}")
        return 1

    print(
        f"OK: schema ({len(schema_keys)} props) aligns with and accepts graph ScanResult; "
        f"required={sorted(required)}; {coverage}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
