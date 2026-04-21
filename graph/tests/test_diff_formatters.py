"""test_diff_formatters.py — Tests for diff_formatters.py (summarize, format_text)."""

from __future__ import annotations

import json
from pathlib import Path

from diff_formatters import format_text, summarize
from diff_scans import diff_scans
from models import ScanResult

FIXTURE = Path(__file__).parent / "fixture_minimal.json"


def _load_fixture() -> ScanResult:
    return ScanResult.model_validate(json.loads(FIXTURE.read_text()))


# ── summarize ────────────────────────────────────────────────────────────────

def test_summarize_keys():
    """All expected metric keys are present in summary dict."""
    scan = _load_fixture()
    diff = diff_scans(scan, scan)
    s = summarize(diff, scan, scan)

    expected_keys = {
        "apps_before", "apps_after", "apps_delta",
        "injectable_before", "injectable_after", "injectable_delta",
        "tcc_grants_before", "tcc_grants_after", "tcc_grants_delta",
        "persistence_before", "persistence_after", "persistence_delta",
        "new_tcc_grants", "removed_tcc_grants", "changed_tcc_grants",
        "new_injectable_apps", "fixed_injectable_apps",
        "physical_posture_changes", "remote_access_changes",
        "icloud_posture_changes",
    }
    assert expected_keys == set(s.keys())


def test_summarize_identical_scans_zero_deltas():
    """Identical scans produce zero deltas."""
    scan = _load_fixture()
    diff = diff_scans(scan, scan)
    s = summarize(diff, scan, scan)

    assert s["apps_delta"] == 0
    assert s["injectable_delta"] == 0
    assert s["tcc_grants_delta"] == 0
    assert s["persistence_delta"] == 0
    assert s["new_tcc_grants"] == 0
    assert s["removed_tcc_grants"] == 0


# ── format_text ──────────────────────────────────────────────────────────────

def test_format_text_header():
    """Output contains hostname."""
    scan = _load_fixture()
    diff = diff_scans(scan, scan)
    s = summarize(diff, scan, scan)
    output = format_text(diff, s)

    assert "test-mac" in output


def test_format_text_no_changes():
    """Identical scans produce 'No security-relevant changes detected.'"""
    scan = _load_fixture()
    diff = diff_scans(scan, scan)
    s = summarize(diff, scan, scan)
    output = format_text(diff, s)

    assert "No security-relevant changes detected." in output


def test_format_text_app_changes():
    """Diff with added app shows [+] marker."""
    before = _load_fixture()
    after_data = json.loads(FIXTURE.read_text())
    after_data["applications"].append({
        "name": "NewApp",
        "bundle_id": "com.example.newapp",
        "path": "/Applications/NewApp.app",
        "version": "1.0",
        "team_id": "TEAM123",
        "hardened_runtime": True,
        "library_validation": True,
        "is_electron": False,
        "is_system": False,
        "signed": True,
        "entitlements": [],
        "is_adhoc_signed": False,
        "signing_certificate_cn": None,
        "signing_certificate_sha256": None,
        "certificate_expires": None,
        "is_certificate_expired": False,
        "certificate_chain_length": None,
        "certificate_trust_valid": None,
        "certificate_chain": [],
        "injection_methods": [],
    })
    after = ScanResult.model_validate(after_data)

    diff = diff_scans(before, after)
    s = summarize(diff, before, after)
    output = format_text(diff, s)

    assert "[+]" in output
    assert "com.example.newapp" in output
