"""test_diff_scans.py - Tests for diff_scans.py diff functions.

All tests are pure Python - no Neo4j required. Builds ScanResult objects
from the fixture JSON and modifies fields to test each diff function.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import TestCase

from conftest import clone_clean_application
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

FIXTURE = Path(__file__).parent / "fixtures" / "minimal_scan.json"


def _load_fixture() -> ScanResult:
    return ScanResult.model_validate(json.loads(FIXTURE.read_text()))


def _load_raw() -> dict:
    return json.loads(FIXTURE.read_text())


def _make_scan(data: dict) -> ScanResult:
    return ScanResult.model_validate(data)


# ── TestDiffApps ─────────────────────────────────────────────────────────────

checks = TestCase()


class TestDiffApps:
    def test_no_changes(self):
        scan = _load_fixture()
        diff = diff_apps(scan, scan)
        checks.assertEqual(diff.added, [])
        checks.assertEqual(diff.removed, [])

    def test_app_added(self):
        before = _load_fixture()
        after_data = _load_raw()
        added_app = clone_clean_application(
            after_data["applications"][0],
            name="NewApp",
            bundle_id="com.example.newapp",
            path="/Applications/NewApp.app",
            team_id="T1",
        )
        after_data["applications"].append(added_app)
        after = _make_scan(after_data)
        diff = diff_apps(before, after)
        checks.assertEqual(len(diff.added), 1)
        checks.assertIn("com.example.newapp", diff.added[0])

    def test_app_removed(self):
        before = _load_fixture()
        after_data = _load_raw()
        after_data["applications"] = after_data["applications"][:1]
        after = _make_scan(after_data)
        diff = diff_apps(before, after)
        checks.assertGreaterEqual(len(diff.removed), 1)


# ── TestDiffTCC ──────────────────────────────────────────────────────────────


class TestDiffTCC:
    def test_no_changes(self):
        scan = _load_fixture()
        diff = diff_tcc(scan, scan)
        checks.assertEqual(diff.added, [])
        checks.assertEqual(diff.removed, [])
        checks.assertEqual(diff.changed, [])

    def test_grant_added(self):
        before = _load_fixture()
        after_data = _load_raw()
        after_data["tcc_grants"].append(
            {
                "service": "kTCCServicePhotos",
                "display_name": "Photos",
                "client": "com.example.newapp",
                "client_type": 0,
                "auth_value": 2,
                "auth_reason": 1,
                "scope": "user",
                "last_modified": 1710748800,
            }
        )
        after = _make_scan(after_data)
        diff = diff_tcc(before, after)
        checks.assertEqual(len(diff.added), 1)
        checks.assertEqual(diff.added[0]["service"], "kTCCServicePhotos")

    def test_grant_removed(self):
        before = _load_fixture()
        after_data = _load_raw()
        after_data["tcc_grants"] = after_data["tcc_grants"][:1]
        after = _make_scan(after_data)
        diff = diff_tcc(before, after)
        checks.assertGreaterEqual(len(diff.removed), 1)

    def test_grant_changed(self):
        before = _load_fixture()
        after_data = _load_raw()
        # Change auth_value of the first grant (was 2 = allowed → 0 = denied)
        after_data["tcc_grants"][0]["auth_value"] = 0
        after = _make_scan(after_data)
        diff = diff_tcc(before, after)
        checks.assertEqual(len(diff.changed), 1)


# ── TestDiffInjection ────────────────────────────────────────────────────────


class TestDiffInjection:
    def test_new_injectable_new_app(self):
        """New app that is injectable."""
        before = _load_fixture()
        after_data = _load_raw()
        after_data["applications"].append(
            {
                "name": "InjectableNew",
                "bundle_id": "com.example.inj",
                "path": "/Applications/Inj.app",
                "version": "1.0",
                "team_id": "T1",
                "hardened_runtime": False,
                "library_validation": False,
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
                "injection_methods": ["dyld_insert"],
            }
        )
        after = _make_scan(after_data)
        diff = diff_injection(before, after)
        checks.assertEqual(len(diff.new_injectable), 1)
        checks.assertEqual(diff.new_injectable[0]["reason"], "new_app")

    def test_became_injectable(self):
        """Existing app gains injection methods."""
        before = _load_fixture()
        after_data = _load_raw()
        # Terminal (index 2) has no injection_methods - give it one
        after_data["applications"][2]["injection_methods"] = ["dyld_insert"]
        after = _make_scan(after_data)
        diff = diff_injection(before, after)
        became = [i for i in diff.new_injectable if i["reason"] == "became_injectable"]
        checks.assertEqual(len(became), 1)

    def test_fixed(self):
        """App that was injectable is no longer injectable."""
        before = _load_fixture()
        after_data = _load_raw()
        # iTerm2 (index 0) has injection_methods - clear them
        after_data["applications"][0]["injection_methods"] = []
        after = _make_scan(after_data)
        diff = diff_injection(before, after)
        fixed = [i for i in diff.no_longer_injectable if i["reason"] == "fixed"]
        checks.assertEqual(len(fixed), 1)

    def test_methods_changed(self):
        """App's injection methods change (but still injectable)."""
        before = _load_fixture()
        after_data = _load_raw()
        # Slack (index 1) has 3 methods - change to just one different set
        after_data["applications"][1]["injection_methods"] = ["dyld_insert"]
        after = _make_scan(after_data)
        diff = diff_injection(before, after)
        checks.assertEqual(len(diff.methods_changed), 1)


# ── TestDiffPersistence ──────────────────────────────────────────────────────


class TestDiffPersistence:
    def test_no_changes(self):
        scan = _load_fixture()
        diff = diff_persistence(scan, scan)
        checks.assertEqual(diff.added, [])
        checks.assertEqual(diff.removed, [])

    def test_added(self):
        before = _load_fixture()
        after_data = _load_raw()
        after_data["launch_items"].append(
            {
                "label": "com.example.new",
                "path": "/Library/LaunchDaemons/new.plist",
                "type": "daemon",
                "program": "/usr/bin/new",
                "run_at_load": True,
                "user": "root",
            }
        )
        after = _make_scan(after_data)
        diff = diff_persistence(before, after)
        checks.assertIn("com.example.new", diff.added)

    def test_removed(self):
        before = _load_fixture()
        after_data = _load_raw()
        after_data["launch_items"] = []
        after = _make_scan(after_data)
        diff = diff_persistence(before, after)
        checks.assertEqual(len(diff.removed), 3)


# ── TestDiffEntitlements ─────────────────────────────────────────────────────


class TestDiffEntitlements:
    def test_no_changes(self):
        scan = _load_fixture()
        diff = diff_entitlements(scan, scan)
        checks.assertEqual(diff.apps_gained_critical, [])
        checks.assertEqual(diff.apps_lost_critical, [])

    def test_gained_critical(self):
        before = _load_fixture()
        after_data = _load_raw()
        # Add a critical entitlement to Terminal (index 2)
        after_data["applications"][2]["entitlements"].append(
            {
                "name": "com.apple.security.cs.allow-dyld-environment-variables",
                "is_private": False,
                "category": "injection",
                "is_security_critical": True,
            }
        )
        after = _make_scan(after_data)
        diff = diff_entitlements(before, after)
        checks.assertGreaterEqual(len(diff.apps_gained_critical), 1)

    def test_lost_critical(self):
        before = _load_fixture()
        after_data = _load_raw()
        # Remove all entitlements from iTerm2 (index 0) - it has 2 critical ones
        after_data["applications"][0]["entitlements"] = []
        after = _make_scan(after_data)
        diff = diff_entitlements(before, after)
        checks.assertGreaterEqual(len(diff.apps_lost_critical), 1)


# ── TestDiffSystemPosture ────────────────────────────────────────────────────


class TestDiffSystemPosture:
    def test_no_changes(self):
        scan = _load_fixture()
        checks.assertEqual(diff_system_posture(scan, scan), {})

    def test_sip_changed(self):
        before = _load_fixture()
        after_data = _load_raw()
        after_data["sip_enabled"] = False
        after = _make_scan(after_data)
        changes = diff_system_posture(before, after)
        checks.assertIn("sip_enabled", changes)
        checks.assertIs(changes["sip_enabled"]["before"], True)
        checks.assertIs(changes["sip_enabled"]["after"], False)


# ── TestDiffPhysicalPosture ──────────────────────────────────────────────────


class TestDiffPhysicalPosture:
    def test_no_changes(self):
        scan = _load_fixture()
        diff = diff_physical_posture(scan, scan)
        checks.assertEqual(diff.changes, {})

    def test_bluetooth_changed(self):
        before = _load_fixture()
        after_data = _load_raw()
        after_data["bluetooth_enabled"] = False
        after = _make_scan(after_data)
        diff = diff_physical_posture(before, after)
        checks.assertIn("bluetooth_enabled", diff.changes)


# ── TestDiffRemoteAccess ─────────────────────────────────────────────────────


class TestDiffRemoteAccess:
    def test_no_changes(self):
        scan = _load_fixture()
        diff = diff_remote_access(scan, scan)
        checks.assertEqual(diff.added, [])
        checks.assertEqual(diff.removed, [])
        checks.assertEqual(diff.changed, [])

    def test_service_added(self):
        before = _load_fixture()
        after_data = _load_raw()
        after_data["remote_access_services"].append(
            {
                "service": "screen_sharing",
                "enabled": True,
                "port": 5900,
            }
        )
        after = _make_scan(after_data)
        diff = diff_remote_access(before, after)
        checks.assertEqual(len(diff.added), 1)
        checks.assertEqual(diff.added[0]["service"], "screen_sharing")

    def test_service_removed(self):
        before = _load_fixture()
        after_data = _load_raw()
        after_data["remote_access_services"] = []
        after = _make_scan(after_data)
        diff = diff_remote_access(before, after)
        checks.assertEqual(len(diff.removed), 1)

    def test_service_changed(self):
        before = _load_fixture()
        after_data = _load_raw()
        after_data["remote_access_services"][0]["port"] = 2222
        after = _make_scan(after_data)
        diff = diff_remote_access(before, after)
        checks.assertEqual(len(diff.changed), 1)


# ── TestDiffICloudPosture ────────────────────────────────────────────────────


class TestDiffICloudPosture:
    def test_no_changes(self):
        scan = _load_fixture()
        diff = diff_icloud_posture(scan, scan)
        checks.assertEqual(diff.changes, {})

    def test_icloud_signed_in_changed(self):
        before = _load_fixture()
        after_data = _load_raw()
        after_data["icloud_signed_in"] = False
        after = _make_scan(after_data)
        diff = diff_icloud_posture(before, after)
        checks.assertIn("icloud_signed_in", diff.changes)


# ── TestDiffScansEndToEnd ────────────────────────────────────────────────────


class TestDiffScansEndToEnd:
    def test_identical_scans(self):
        scan = _load_fixture()
        diff = diff_scans(scan, scan)
        checks.assertEqual(diff.hostname, "test-mac")
        checks.assertEqual(diff.apps.added, [])
        checks.assertEqual(diff.apps.removed, [])
        checks.assertEqual(diff.tcc.added, [])
        checks.assertEqual(diff.system_posture, {})

    def test_known_deltas(self):
        """Full diff_scans with a known set of changes."""
        before = _load_fixture()
        after_data = _load_raw()
        # Add an app, remove a TCC grant, change SIP
        added_app = clone_clean_application(
            after_data["applications"][0],
            name="Delta",
            bundle_id="com.example.delta",
            path="/Applications/Delta.app",
            team_id="T1",
        )
        after_data["applications"].append(added_app)
        after_data["tcc_grants"] = after_data["tcc_grants"][:2]
        after_data["sip_enabled"] = False
        after = _make_scan(after_data)

        diff = diff_scans(before, after)
        checks.assertEqual(len(diff.apps.added), 1)
        checks.assertGreaterEqual(len(diff.tcc.removed), 1)
        checks.assertIn("sip_enabled", diff.system_posture)
