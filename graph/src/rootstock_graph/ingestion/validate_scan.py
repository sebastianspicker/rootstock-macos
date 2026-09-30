#!/usr/bin/env python3
"""
rootstock-graph-validate-scan - Validate a Rootstock collector scan JSON output.

Checks the scan against the packaged legacy collector schema, the shared
Pydantic models, and semantic rules the schema cannot express.

Usage:
    rootstock-graph-validate-scan <scan-file.json>

Exit code 0 on success, 1 on validation failure.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

import jsonschema

from ..models import ScanResult
from ..paths import package_resource_dir

SCHEMA_PATH = package_resource_dir("contracts").joinpath(
    "collector-scan", "legacy-unversioned.schema.json"
)
KNOWN_ENTITLEMENT_CATEGORIES = {
    "tcc",
    "injection",
    "privilege",
    "sandbox",
    "keychain",
    "network",
    "icloud",
    "other",
}


def load_schema() -> dict | None:
    if not SCHEMA_PATH.is_file():
        print(f"ERROR: Schema not found at {SCHEMA_PATH}", file=sys.stderr)
        return None
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


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
    errors.extend(validate_timestamp(data))
    errors.extend(validate_required_strings(data))
    errors.extend(validate_application_identity(data))
    errors.extend(validate_entitlement_categories(data))
    return errors


def validate_timestamp(data):
    """Validate timestamp formatting."""
    errors = []
    # timestamp must be parseable ISO 8601
    ts = data.get("timestamp", "")
    try:
        datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"  Semantic: timestamp is not valid ISO 8601 UTC: {ts!r}")
    return errors


def validate_required_strings(data):
    """Validate required top-level string fields."""
    errors = []
    # No empty strings in required string fields
    for field in ("hostname", "macos_version", "collector_version"):
        if not data.get(field, "").strip():
            errors.append(f"  Semantic: required field '{field}' is empty")
    return errors


def validate_application_identity(data):
    """Validate application identity uniqueness and required fields."""
    errors = []
    # No duplicate application observations by (bundle_id, path)
    bundle_ids = [(a.get("bundle_id"), a.get("path")) for a in data.get("applications", [])]
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
    return errors


def validate_entitlement_categories(data):
    """Validate entitlement category values."""
    errors = []
    # Entitlement categories must be from known set
    for app in data.get("applications", []):
        for ent in app.get("entitlements", []):
            if ent.get("category") not in KNOWN_ENTITLEMENT_CATEGORIES:
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


def _load_scan(path: Path) -> tuple[bool, object]:
    """Return (loaded, scan), reporting why the scan cannot be read."""
    if not path.exists():
        print(f"ERROR: File not found: {path}", file=sys.stderr)
        return False, None
    try:
        with open(path) as f:
            return True, json.load(f)
    except json.JSONDecodeError as e:
        print(f"✗ Invalid JSON: {e}")
        return False, None


def _report(path: Path, data, all_errors: list[str]) -> int:
    if all_errors:
        print(f"✗ Invalid: {path}")
        for err in all_errors:
            print(err)
        return 1
    apps = len(data.get("applications", []))
    grants = len(data.get("tcc_grants", []))
    errors = len(data.get("errors", []))
    print(f"✓ Valid: {path} ({apps} apps, {grants} TCC grants, {errors} collection errors)")
    return 0


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <scan-file.json>", file=sys.stderr)
        return 1

    path = Path(sys.argv[1])
    loaded, data = _load_scan(path)
    if not loaded:
        return 1

    schema = load_schema()
    if schema is None:
        return 1

    schema_errors = validate_schema(data, schema)
    model_errors = validate_models(data)
    # Semantic checks index into an object; a non-object root already failed the schema.
    semantic_errors = validate_semantics(data) if isinstance(data, dict) else []
    return _report(path, data, schema_errors + model_errors + semantic_errors)


if __name__ == "__main__":
    sys.exit(main())
