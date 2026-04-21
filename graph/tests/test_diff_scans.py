"""test_diff_scans.py — Tests for diff_scans.py diff functions.

All tests are pure Python — no Neo4j required. Builds ScanResult objects
from the fixture JSON and modifies fields to test each diff function.
"""

from __future__ import annotations

import json
from pathlib import Path

from diff_scans import (
    diff_apps,
    diff_entitlements,
    diff_icloud_posture,
    diff_injection,
    diff_persistence,
    diff_physical_posture,
    diff_remote_access,
    diff_scans,
    diff_system_posture,
    diff_tcc,
)
from models import ScanResult

FIXTURE = Path(__file__).parent / "fixture_minimal.json"


def _load_fixture() -> ScanResult:
    return ScanResult.model_validate(json.loads(FIXTURE.read_text()))


def _load_raw() -> dict:
    return json.loads(FIXTURE.read_text())


def _make_scan(data: dict) -> ScanResult:
    return ScanResult.model_validate(data)


# ── TestDiffApps ─────────────────────────────────────────────────────────────

class TestDiffApps:
    def test_no_changes(self):
        scan = _load_fixture()
        diff = diff_apps(scan, scan)
        assert diff.added == []
        assert diff.removed == []

    def test_app_added(self):
        before = _load_fixture()
        after_data = _load_raw()
        after_data["applications"].append({
            "name": "NewApp", "bundle_id": "com.example.newapp",
            "path": "/Applications/NewApp.app", "version": "1.0",
            "team_id": "T1", "hardened_runtime": True,
            "library_validation": True, "is_electron": False,
            "is_system": False, "signed": True, "entitlements": [],
            "is_adhoc_signed": False, "signing_certificate_cn": None,
            "signing_certificate_sha256": None, "certificate_expires": None,
            "is_certificate_expired": False, "certificate_chain_length": None,
            "certificate_trust_valid": None, "certificate_chain": [],
            "injection_methods": [],
        })
        after = _make_scan(after_data)
        diff = diff_apps(before, after)
        assert len(diff.added) == 1
        assert "com.example.newapp" in diff.added[0]

    def test_app_removed(self):
        before = _load_fixture()
        after_data = _load_raw()
        after_data["applications"] = after_data["applications"][:1]
        after = _make_scan(after_data)
        diff = diff_apps(before, after)
        assert len(diff.removed) >= 1


# ── TestDiffTCC ──────────────────────────────────────────────────────────────

class TestDiffTCC:
    def test_no_changes(self):
        scan = _load_fixture()
        diff = diff_tcc(scan, scan)
        assert diff.added == []
        assert diff.removed == []
        assert diff.changed == []

    def test_grant_added(self):
        before = _load_fixture()
        after_data = _load_raw()
        after_data["tcc_grants"].append({
            "service": "kTCCServicePhotos", "display_name": "Photos",
            "client": "com.example.newapp", "client_type": 0,
            "auth_value": 2, "auth_reason": 1, "scope": "user",
            "last_modified": 1710748800,
        })
        after = _make_scan(after_data)
        diff = diff_tcc(before, after)
        assert len(diff.added) == 1
        assert diff.added[0]["service"] == "kTCCServicePhotos"

    def test_grant_removed(self):
        before = _load_fixture()
        after_data = _load_raw()
        after_data["tcc_grants"] = after_data["tcc_grants"][:1]
        after = _make_scan(after_data)
        diff = diff_tcc(before, after)
        assert len(diff.removed) >= 1

    def test_grant_changed(self):
        before = _load_fixture()
        after_data = _load_raw()
        # Change auth_value of the first grant (was 2 = allowed → 0 = denied)
        after_data["tcc_grants"][0]["auth_value"] = 0
        after = _make_scan(after_data)
        diff = diff_tcc(before, after)
        assert len(diff.changed) == 1


# ── TestDiffInjection ────────────────────────────────────────────────────────

class TestDiffInjection:
    def test_new_injectable_new_app(self):
        """New app that is injectable."""
        before = _load_fixture()
        after_data = _load_raw()
        after_data["applications"].append({
            "name": "InjectableNew", "bundle_id": "com.example.inj",
            "path": "/Applications/Inj.app", "version": "1.0",
            "team_id": "T1", "hardened_runtime": False,
            "library_validation": False, "is_electron": False,
            "is_system": False, "signed": True, "entitlements": [],
            "is_adhoc_signed": False, "signing_certificate_cn": None,
            "signing_certificate_sha256": None, "certificate_expires": None,
            "is_certificate_expired": False, "certificate_chain_length": None,
            "certificate_trust_valid": None, "certificate_chain": [],
            "injection_methods": ["dyld_insert"],
        })
        after = _make_scan(after_data)
        diff = diff_injection(before, after)
        assert len(diff.new_injectable) == 1
        assert diff.new_injectable[0]["reason"] == "new_app"

    def test_became_injectable(self):
        """Existing app gains injection methods."""
        before = _load_fixture()
        after_data = _load_raw()
        # Terminal (index 2) has no injection_methods — give it one
        after_data["applications"][2]["injection_methods"] = ["dyld_insert"]
        after = _make_scan(after_data)
        diff = diff_injection(before, after)
        became = [i for i in diff.new_injectable if i["reason"] == "became_injectable"]
        assert len(became) == 1

    def test_fixed(self):
        """App that was injectable is no longer injectable."""
        before = _load_fixture()
        after_data = _load_raw()
        # iTerm2 (index 0) has injection_methods — clear them
        after_data["applications"][0]["injection_methods"] = []
        after = _make_scan(after_data)
        diff = diff_injection(before, after)
        fixed = [i for i in diff.no_longer_injectable if i["reason"] == "fixed"]
        assert len(fixed) == 1

    def test_methods_changed(self):
        """App's injection methods change (but still injectable)."""
        before = _load_fixture()
        after_data = _load_raw()
        # Slack (index 1) has 3 methods — change to just one different set
        after_data["applications"][1]["injection_methods"] = ["dyld_insert"]
        after = _make_scan(after_data)
        diff = diff_injection(before, after)
        assert len(diff.methods_changed) == 1


# ── TestDiffPersistence ──────────────────────────────────────────────────────

class TestDiffPersistence:
    def test_no_changes(self):
        scan = _load_fixture()
        diff = diff_persistence(scan, scan)
        assert diff.added == []
        assert diff.removed == []

    def test_added(self):
        before = _load_fixture()
        after_data = _load_raw()
        after_data["launch_items"].append({
            "label": "com.example.new", "path": "/Library/LaunchDaemons/new.plist",
            "type": "daemon", "program": "/usr/bin/new", "run_at_load": True, "user": "root",
        })
        after = _make_scan(after_data)
        diff = diff_persistence(before, after)
        assert "com.example.new" in diff.added

    def test_removed(self):
        before = _load_fixture()
        after_data = _load_raw()
        after_data["launch_items"] = []
        after = _make_scan(after_data)
        diff = diff_persistence(before, after)
        assert len(diff.removed) == 3


# ── TestDiffEntitlements ─────────────────────────────────────────────────────

class TestDiffEntitlements:
    def test_no_changes(self):
        scan = _load_fixture()
        diff = diff_entitlements(scan, scan)
        assert diff.apps_gained_critical == []
        assert diff.apps_lost_critical == []

    def test_gained_critical(self):
        before = _load_fixture()
        after_data = _load_raw()
        # Add a critical entitlement to Terminal (index 2)
        after_data["applications"][2]["entitlements"].append({
            "name": "com.apple.security.cs.allow-dyld-environment-variables",
            "is_private": False, "category": "injection", "is_security_critical": True,
        })
        after = _make_scan(after_data)
        diff = diff_entitlements(before, after)
        assert len(diff.apps_gained_critical) >= 1

    def test_lost_critical(self):
        before = _load_fixture()
        after_data = _load_raw()
        # Remove all entitlements from iTerm2 (index 0) — it has 2 critical ones
        after_data["applications"][0]["entitlements"] = []
        after = _make_scan(after_data)
        diff = diff_entitlements(before, after)
        assert len(diff.apps_lost_critical) >= 1


# ── TestDiffSystemPosture ────────────────────────────────────────────────────

class TestDiffSystemPosture:
    def test_no_changes(self):
        scan = _load_fixture()
        assert diff_system_posture(scan, scan) == {}

    def test_sip_changed(self):
        before = _load_fixture()
        after_data = _load_raw()
        after_data["sip_enabled"] = False
        after = _make_scan(after_data)
        changes = diff_system_posture(before, after)
        assert "sip_enabled" in changes
        assert changes["sip_enabled"]["before"] is True
        assert changes["sip_enabled"]["after"] is False


# ── TestDiffPhysicalPosture ──────────────────────────────────────────────────

class TestDiffPhysicalPosture:
    def test_no_changes(self):
        scan = _load_fixture()
        diff = diff_physical_posture(scan, scan)
        assert diff.changes == {}

    def test_bluetooth_changed(self):
        before = _load_fixture()
        after_data = _load_raw()
        after_data["bluetooth_enabled"] = False
        after = _make_scan(after_data)
        diff = diff_physical_posture(before, after)
        assert "bluetooth_enabled" in diff.changes


# ── TestDiffRemoteAccess ─────────────────────────────────────────────────────

class TestDiffRemoteAccess:
    def test_no_changes(self):
        scan = _load_fixture()
        diff = diff_remote_access(scan, scan)
        assert diff.added == []
        assert diff.removed == []
        assert diff.changed == []

    def test_service_added(self):
        before = _load_fixture()
        after_data = _load_raw()
        after_data["remote_access_services"].append({
            "service": "screen_sharing", "enabled": True, "port": 5900,
        })
        after = _make_scan(after_data)
        diff = diff_remote_access(before, after)
        assert len(diff.added) == 1
        assert diff.added[0]["service"] == "screen_sharing"

    def test_service_removed(self):
        before = _load_fixture()
        after_data = _load_raw()
        after_data["remote_access_services"] = []
        after = _make_scan(after_data)
        diff = diff_remote_access(before, after)
        assert len(diff.removed) == 1

    def test_service_changed(self):
        before = _load_fixture()
        after_data = _load_raw()
        after_data["remote_access_services"][0]["port"] = 2222
        after = _make_scan(after_data)
        diff = diff_remote_access(before, after)
        assert len(diff.changed) == 1


# ── TestDiffICloudPosture ────────────────────────────────────────────────────

class TestDiffICloudPosture:
    def test_no_changes(self):
        scan = _load_fixture()
        diff = diff_icloud_posture(scan, scan)
        assert diff.changes == {}

    def test_icloud_signed_in_changed(self):
        before = _load_fixture()
        after_data = _load_raw()
        after_data["icloud_signed_in"] = False
        after = _make_scan(after_data)
        diff = diff_icloud_posture(before, after)
        assert "icloud_signed_in" in diff.changes


# ── TestDiffScansEndToEnd ────────────────────────────────────────────────────

class TestDiffScansEndToEnd:
    def test_identical_scans(self):
        scan = _load_fixture()
        diff = diff_scans(scan, scan)
        assert diff.hostname == "test-mac"
        assert diff.apps.added == []
        assert diff.apps.removed == []
        assert diff.tcc.added == []
        assert diff.system_posture == {}

    def test_known_deltas(self):
        """Full diff_scans with a known set of changes."""
        before = _load_fixture()
        after_data = _load_raw()
        # Add an app, remove a TCC grant, change SIP
        after_data["applications"].append({
            "name": "Delta", "bundle_id": "com.example.delta",
            "path": "/Applications/Delta.app", "version": "1.0",
            "team_id": "T1", "hardened_runtime": True,
            "library_validation": True, "is_electron": False,
            "is_system": False, "signed": True, "entitlements": [],
            "is_adhoc_signed": False, "signing_certificate_cn": None,
            "signing_certificate_sha256": None, "certificate_expires": None,
            "is_certificate_expired": False, "certificate_chain_length": None,
            "certificate_trust_valid": None, "certificate_chain": [],
            "injection_methods": [],
        })
        after_data["tcc_grants"] = after_data["tcc_grants"][:2]
        after_data["sip_enabled"] = False
        after = _make_scan(after_data)

        diff = diff_scans(before, after)
        assert len(diff.apps.added) == 1
        assert len(diff.tcc.removed) >= 1
        assert "sip_enabled" in diff.system_posture
