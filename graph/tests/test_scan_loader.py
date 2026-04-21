"""test_scan_loader.py — Tests for scan_loader.py and duplicate bundle_id logging."""

from __future__ import annotations

import json
import logging
from pathlib import Path


from scan_loader import load_scan
from models import ScanResult

FIXTURE = Path(__file__).parent / "fixture_minimal.json"


def test_valid_json_loads(tmp_path):
    """Valid fixture JSON loads into a ScanResult."""
    content = FIXTURE.read_text()
    target = tmp_path / "scan.json"
    target.write_text(content)

    result = load_scan(target)
    assert isinstance(result, ScanResult)
    assert result.hostname == "test-mac"


def test_invalid_json_returns_none(tmp_path, capsys):
    """Garbage content returns None and prints error to stderr."""
    target = tmp_path / "bad.json"
    target.write_text("not json at all {{{")

    result = load_scan(target)
    assert result is None
    assert "Cannot read" in capsys.readouterr().err


def test_schema_validation_failure(tmp_path, capsys):
    """Valid JSON missing required fields returns None."""
    target = tmp_path / "incomplete.json"
    target.write_text(json.dumps({"scan_id": "abc"}))

    result = load_scan(target)
    assert result is None
    assert "schema validation" in capsys.readouterr().err.lower()


def test_duplicate_bundle_ids_logs_warning(caplog):
    """Duplicate bundle_ids in applications triggers a logging.warning."""
    data = json.loads(FIXTURE.read_text())
    # Duplicate the first application
    data["applications"].append(data["applications"][0])

    with caplog.at_level(logging.WARNING, logger="models"):
        result = ScanResult.model_validate(data)

    assert result is not None
    assert any("Duplicate bundle_id" in msg for msg in caplog.messages)
