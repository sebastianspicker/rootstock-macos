from __future__ import annotations

from unittest import TestCase

import json
from pathlib import Path

import jsonschema
import pytest

from rootstock_graph.ingestion import validate_scan
from rootstock_graph.models import ScanResult


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "contracts" / "collector-scan" / "legacy-unversioned.schema.json"
DEMO_SCAN_PATH = ROOT / "examples" / "demo-scan.json"


checks = TestCase()


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def test_demo_scan_matches_schema_and_models() -> None:
    data = _load_json(DEMO_SCAN_PATH)
    schema = _load_json(SCHEMA_PATH)

    jsonschema.Draft202012Validator(schema).validate(data)
    ScanResult.model_validate(data)
    checks.assertEqual(validate_scan.validate_semantics(data), [])


def test_duplicate_bundle_ids_are_allowed_when_paths_differ() -> None:
    data = _load_json(DEMO_SCAN_PATH)
    duplicate = dict(data["applications"][0])
    duplicate["path"] = "/Applications/Alternate/iTerm.app"
    data["applications"].append(duplicate)

    checks.assertEqual(validate_scan.validate_semantics(data), [])
    result = ScanResult.model_validate(data)
    matching = [
        app for app in result.applications if app.bundle_id == data["applications"][0]["bundle_id"]
    ]
    checks.assertGreaterEqual(
        {app.path for app in matching},
        {
            data["applications"][0]["path"],
            duplicate["path"],
        },
    )


@pytest.mark.parametrize("text", ["[]", "1", '"scan"', "null"])
def test_non_object_root_is_reported_as_invalid(
    text: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    scan = tmp_path / "scan.json"
    scan.write_text(text)
    monkeypatch.setattr("sys.argv", ["rootstock-graph-validate-scan", str(scan)])

    checks.assertEqual(validate_scan.main(), 1)
    output = capsys.readouterr()
    checks.assertIn("Invalid", output.out)
    checks.assertIn("Schema: [(root)]", output.out)
    checks.assertNotIn("Traceback", output.out + output.err)
