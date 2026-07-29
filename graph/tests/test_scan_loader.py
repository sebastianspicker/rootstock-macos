"""test_scan_loader.py - Tests for scan_loader.py and duplicate bundle_id logging."""

from __future__ import annotations

from unittest import TestCase

import json
import logging
from pathlib import Path


from scan_loader import load_scan
from models import ScanResult

FIXTURE = Path(__file__).parent / "fixtures" / "minimal_scan.json"


checks = TestCase()


def test_valid_json_loads(tmp_path):
    """Valid fixture JSON loads into a ScanResult."""
    content = FIXTURE.read_text()
    target = tmp_path / "scan.json"
    target.write_text(content)

    result = load_scan(target)
    checks.assertTrue(isinstance(result, ScanResult))
    checks.assertEqual(result.hostname, "test-mac")


def test_invalid_json_returns_none(tmp_path, capsys):
    """Garbage content returns None and prints error to stderr."""
    target = tmp_path / "bad.json"
    target.write_text("not json at all {{{")

    result = load_scan(target)
    checks.assertIsNone(result)
    checks.assertIn("Cannot read", capsys.readouterr().err)


def test_schema_validation_failure(tmp_path, capsys):
    """Valid JSON missing required fields returns None."""
    target = tmp_path / "incomplete.json"
    target.write_text(json.dumps({"scan_id": "abc"}))

    result = load_scan(target)
    checks.assertIsNone(result)
    checks.assertIn("schema validation", capsys.readouterr().err.lower())


def test_exact_duplicate_application_logs_warning_and_is_deduped(caplog):
    """Exact duplicate applications are deduped without dropping path-distinct apps."""
    data = json.loads(FIXTURE.read_text())
    original_count = len(data["applications"])
    data["applications"].append(data["applications"][0])

    with caplog.at_level(logging.WARNING, logger="models"):
        result = ScanResult.model_validate(data)

    checks.assertIsNotNone(result)
    checks.assertEqual(len(result.applications), original_count)
    checks.assertTrue(any("Duplicate bundle_id/path" in msg for msg in caplog.messages))


def test_same_bundle_id_with_different_path_is_preserved(caplog):
    """A moved or duplicated bundle at a different path remains distinct."""
    data = json.loads(FIXTURE.read_text())
    duplicate_path = "/Applications/Alternate/iTerm.app"
    duplicate = dict(data["applications"][0])
    duplicate["path"] = duplicate_path
    data["applications"].append(duplicate)

    with caplog.at_level(logging.WARNING, logger="models"):
        result = ScanResult.model_validate(data)

    matching = [
        app
        for app in result.applications
        if app.bundle_id == data["applications"][0]["bundle_id"]
    ]
    matching_paths = {app.path for app in matching}
    expected_paths = {data["applications"][0]["path"], duplicate_path}
    checks.assertGreaterEqual(matching_paths, expected_paths)
    checks.assertFalse(caplog.messages)
