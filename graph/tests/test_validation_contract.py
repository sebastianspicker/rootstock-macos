from __future__ import annotations

from unittest import TestCase

import importlib.util
import json
from pathlib import Path

import jsonschema

from models import ScanResult


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "collector" / "schema" / "scan-result.schema.json"
DEMO_SCAN_PATH = ROOT / "examples" / "demo-scan.json"
FIXTURE_SCAN_PATH = ROOT / "graph" / "tests" / "fixture_minimal.json"
VALIDATOR_PATH = ROOT / "scripts" / "validate-scan.py"


checks = TestCase()

spec = importlib.util.spec_from_file_location("validate_scan", VALIDATOR_PATH)
validate_scan = importlib.util.module_from_spec(spec)
checks.assertTrue(spec and spec.loader)
spec.loader.exec_module(validate_scan)


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def test_demo_scan_matches_schema_and_models() -> None:
    data = _load_json(DEMO_SCAN_PATH)
    schema = _load_json(SCHEMA_PATH)

    jsonschema.Draft202012Validator(schema).validate(data)
    ScanResult.model_validate(data)
    checks.assertEqual(validate_scan.validate_semantics(data), [])


def test_fixture_scan_matches_schema_and_models() -> None:
    data = _load_json(FIXTURE_SCAN_PATH)
    schema = _load_json(SCHEMA_PATH)

    jsonschema.Draft202012Validator(schema).validate(data)
    ScanResult.model_validate(data)
    checks.assertEqual(validate_scan.validate_semantics(data), [])


def test_duplicate_bundle_ids_are_allowed_when_paths_differ() -> None:
    data = _load_json(FIXTURE_SCAN_PATH)
    duplicate = dict(data["applications"][0])
    duplicate["path"] = "/Applications/Alternate/iTerm.app"
    data["applications"].append(duplicate)

    checks.assertEqual(validate_scan.validate_semantics(data), [])
    result = ScanResult.model_validate(data)
    matching = [
        app
        for app in result.applications
        if app.bundle_id == data["applications"][0]["bundle_id"]
    ]
    checks.assertGreaterEqual(
        {app.path for app in matching},
        {
            data["applications"][0]["path"],
            duplicate["path"],
        },
    )
