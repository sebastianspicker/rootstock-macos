#!/usr/bin/env python3
"""
validate-scan.py — Validate a Rootstock scan JSON output.

Usage:
    python3 scripts/validate-scan.py <scan-file.json>

Exit code 0 on success, 1 on validation failure.
"""

import importlib.util
import json
import sys
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).parent.parent

try:
    import jsonschema
except ImportError:
    print(
        "ERROR: jsonschema not installed. Run: pip3 install -r graph/requirements.txt",
        file=sys.stderr,
    )
    sys.exit(1)

model_spec = importlib.util.spec_from_file_location(
    "graph_models", ROOT / "graph" / "models.py"
)
if model_spec is None or model_spec.loader is None:
    print(
        "ERROR: graph models not importable. Run: pip3 install -r graph/requirements.txt",
        file=sys.stderr,
    )
    sys.exit(1)

graph_models = importlib.util.module_from_spec(model_spec)
model_spec.loader.exec_module(graph_models)
graph_models.ScanResult.model_rebuild(_types_namespace=vars(graph_models))
ScanResult = graph_models.ScanResult

SCHEMA_PATH = ROOT / "collector" / "schema" / "scan-result.schema.json"


def load_schema():
    if not SCHEMA_PATH.exists():
        print(f"ERROR: Schema not found at {SCHEMA_PATH}", file=sys.stderr)
        sys.exit(1)
    with open(SCHEMA_PATH) as f:
        return json.load(f)


def validate_schema(data, schema):
    """Validate data against JSON Schema. Returns list of error strings."""
    errors = []
    validator = jsonschema.Draft202012Validator(schema)
    for err in validator.iter_errors(data):
        path = " → ".join(str(p) for p in err.absolute_path) or "(root)"
        errors.append(f"  Schema: [{path}] {err.message}")
    return errors


def validate_semantics(data):
    """Perform semantic checks beyond JSON Schema. Returns list of error strings."""
    errors = []

    # timestamp must be parseable ISO 8601
    ts = data.get("timestamp", "")
    try:
        datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"  Semantic: timestamp is not valid ISO 8601 UTC: {ts!r}")

    # No empty strings in required string fields
    for field in ("hostname", "macos_version", "collector_version"):
        if not data.get(field, "").strip():
            errors.append(f"  Semantic: required field '{field}' is empty")

    # No duplicate application observations by (bundle_id, path)
    bundle_ids = [
        (a.get("bundle_id"), a.get("path")) for a in data.get("applications", [])
    ]
    seen = set()
    for bid in bundle_ids:
        if bid in seen:
            errors.append(f"  Semantic: duplicate application observation: {bid!r}")
        seen.add(bid)

    # No empty strings in application required string fields
    for app in data.get("applications", []):
        for field in ("name", "bundle_id", "path"):
            if not app.get(field, "").strip():
                errors.append(
                    f"  Semantic: application {app.get('bundle_id', '?')!r} has empty '{field}'"
                )

    # Entitlement categories must be from known set
    known_categories = {
        "tcc",
        "injection",
        "privilege",
        "sandbox",
        "keychain",
        "network",
        "icloud",
        "other",
    }
    for app in data.get("applications", []):
        for ent in app.get("entitlements", []):
            if ent.get("category") not in known_categories:
                errors.append(
                    f"  Semantic: unknown entitlement category {ent.get('category')!r} "
                    f"in {app.get('bundle_id')!r}"
                )

    return errors


def validate_models(data):
    """Validate data against the shared Pydantic contract."""
    try:
        ScanResult.model_validate(data)
    except Exception as exc:
        return [f"  Model: {exc}"]
    return []


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <scan-file.json>", file=sys.stderr)
        sys.exit(1)

    path = Path(sys.argv[1])
    if not path.exists():
        print(f"ERROR: File not found: {path}", file=sys.stderr)
        sys.exit(1)

    # Load JSON
    try:
        with open(path) as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"✗ Invalid JSON: {e}")
        sys.exit(1)

    schema = load_schema()

    schema_errors = validate_schema(data, schema)
    model_errors = validate_models(data)
    semantic_errors = validate_semantics(data)
    all_errors = schema_errors + model_errors + semantic_errors

    if all_errors:
        print(f"✗ Invalid: {path}")
        for err in all_errors:
            print(err)
        sys.exit(1)
    else:
        apps = len(data.get("applications", []))
        grants = len(data.get("tcc_grants", []))
        errors = len(data.get("errors", []))
        print(
            f"✓ Valid: {path} "
            f"({apps} apps, {grants} TCC grants, {errors} collection errors)"
        )
        sys.exit(0)


if __name__ == "__main__":
    main()
