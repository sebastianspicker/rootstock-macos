#!/usr/bin/env python3
"""Check collector scan JSON contract field alignment.

Source of truth for top-level keys: collector/schema/scan-result.schema.json

Also compares:
  - graph/models.py ScanResult field aliases (Pydantic)
  - collector/Sources/Models/ScanResult.swift CodingKeys (best-effort regex)

Usage:
    python3 scripts/check-scan-contract-fields.py
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "collector" / "schema" / "scan-result.schema.json"
MODELS_PATH = ROOT / "graph" / "models.py"
SWIFT_PATH = ROOT / "collector" / "Sources" / "Models" / "ScanResult.swift"


def load_schema_keys() -> tuple[set[str], set[str]]:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    props = set(schema.get("properties", {}).keys())
    required = set(schema.get("required", []))
    return props, required


def load_pydantic_keys() -> set[str]:
    spec = importlib.util.spec_from_file_location("graph_models", MODELS_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {MODELS_PATH}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.ScanResult.model_rebuild(_types_namespace=vars(mod))
    # model_fields keys are Python names; serialization aliases may differ
    keys: set[str] = set()
    for name, field in mod.ScanResult.model_fields.items():
        alias = field.alias or field.serialization_alias or name
        keys.add(str(alias))
    return keys


def _camel_to_snake(name: str) -> str:
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


def load_swift_coding_keys() -> set[str] | None:
    if not SWIFT_PATH.is_file():
        return None
    text = SWIFT_PATH.read_text(encoding="utf-8")
    # Prefer the top-level ScanResult.CodingKeys block (last large enum is fine;
    # collect all CodingKeys string mappings and bare cases).
    keys: set[str] = set()
    for m in re.finditer(
        r"case\s+(\w+)(?:\s*=\s*\"([a-z0-9_]+)\")?",
        text,
    ):
        case_name, explicit = m.group(1), m.group(2)
        if explicit:
            keys.add(explicit)
        else:
            # String CodingKey uses the case name as the JSON key when unaliased
            # (e.g. case timestamp → "timestamp"; case applications → "applications").
            keys.add(case_name)
            keys.add(_camel_to_snake(case_name))
    return keys or None


def _pydantic_alignment_errors(schema_keys: set[str], required: set[str]) -> list[str]:
    errors: list[str] = []
    try:
        pydantic_keys = load_pydantic_keys()
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: cannot load graph models: {exc}", file=sys.stderr)
        return [f"cannot load graph models: {exc}"]

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


def _swift_alignment_errors(schema_keys: set[str]) -> list[str]:
    swift_keys = load_swift_coding_keys()
    if swift_keys is None:
        return []
    missing_swift = sorted(schema_keys - swift_keys)
    if missing_swift:
        return [
            "schema top-level keys not found in ScanResult.swift CodingKeys strings: "
            f"{missing_swift}"
        ]
    return []


def _success_message(schema_keys: set[str], required: set[str]) -> str:
    swift_keys = load_swift_coding_keys()
    return (
        f"OK: schema ({len(schema_keys)} props) aligns with graph ScanResult; "
        f"required={sorted(required)}"
        + ("; Swift CodingKeys cover top-level" if swift_keys is not None else "")
    )


def main() -> int:
    if not SCHEMA_PATH.is_file():
        print(f"ERROR: schema missing {SCHEMA_PATH}", file=sys.stderr)
        return 1

    schema_keys, required = load_schema_keys()
    errors = _pydantic_alignment_errors(schema_keys, required)
    errors.extend(_swift_alignment_errors(schema_keys))

    if errors:
        print("Scan contract field check FAILED:")
        for e in errors:
            print(f"  - {e}")
        return 1

    print(_success_message(schema_keys, required))
    return 0


if __name__ == "__main__":
    sys.exit(main())
