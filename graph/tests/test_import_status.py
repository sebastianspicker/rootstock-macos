from __future__ import annotations

from unittest import TestCase

import importlib
import sys
from contextlib import nullcontext
from types import SimpleNamespace


def test_import_status_is_complete_only_without_errors_or_skips():
    importer = importlib.import_module("import_scan")

    checks.assertEqual(importer.classify_import_status(0, 0), "complete")
    checks.assertEqual(importer.classify_import_status(1, 0), "partial")
    checks.assertEqual(importer.classify_import_status(0, 1), "partial")


def test_partial_import_warns_but_keeps_success_exit(monkeypatch, tmp_path, capsys):
    importer = importlib.import_module("import_scan")
    input_path = tmp_path / "scan.json"
    input_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["import_scan.py", "--input", str(input_path)])
    monkeypatch.setattr(
        importer, "load_scan", lambda _path: _scan_with_collection_error()
    )
    monkeypatch.setattr(importer, "connect_from_args", lambda _args: _FakeDriver())
    _patch_import_steps(importer, monkeypatch)
    monkeypatch.setattr(
        importer,
        "query_stats",
        lambda _session: (
            {label: 0 for label in importer._NODE_LABELS},
            {rel_type: 0 for rel_type in importer._REL_TYPES},
        ),
    )
    monkeypatch.setattr(
        importer,
        "query_security_summary",
        lambda _session: {"fda_apps": 0, "injectable_apps": 0, "electron_apps": 0},
    )

    exit_code = importer.main()

    captured = capsys.readouterr()
    checks.assertEqual(exit_code, 0)
    checks.assertIn("IMPORT PARTIAL", captured.out)
    checks.assertIn("WARNING: import completed with partial source data", captured.err)


checks = TestCase()


class _FakeDriver:
    def session(self):
        return nullcontext()

    def close(self):
        return None

def _scan_with_collection_error():
    return SimpleNamespace(
        hostname="fixture-host",
        scan_id="scan-fixture",
        macos_version="14.0",
        timestamp="2026-05-28T00:00:00Z",
        collector_version="test",
        applications=[],
        tcc_grants=[],
        xpc_services=[],
        keychain_acls=[],
        mdm_profiles=[],
        launch_items=[],
        local_groups=[],
        remote_access_services=[],
        firewall_status=[],
        login_sessions=[],
        authorization_rights=[],
        authorization_plugins=[],
        system_extensions=[],
        sudoers_rules=[],
        running_processes=[],
        file_acls=[],
        bluetooth_devices=[],
        ad_binding=None,
        kerberos_artifacts=[],
        sandbox_profiles=[],
        errors=[
            SimpleNamespace(source="Kerberos", message="fixture", recoverable=True)
        ],
        elevation=SimpleNamespace(is_root=False, has_fda=False),
        gatekeeper_enabled=None,
        sip_enabled=None,
        filevault_enabled=None,
        lockdown_mode_enabled=None,
        bluetooth_enabled=None,
        bluetooth_discoverable=None,
        screen_lock_enabled=None,
        screen_lock_delay=None,
        display_sleep_timeout=None,
        thunderbolt_security_level=None,
        secure_boot_level=None,
        external_boot_allowed=None,
        icloud_signed_in=None,
        icloud_drive_enabled=None,
        icloud_keychain_enabled=None,
        user_details=[],
    )


def _patch_import_steps(importer, monkeypatch):
    def zero(*_args, **_kwargs):
        return 0

    def pair(*_args, **_kwargs):
        return (0, 0)

    def triple(*_args, **_kwargs):
        return (0, 0, 0)

    def quad(*_args, **_kwargs):
        return (0, 0, 0, 0)

    monkeypatch.setattr(importer, "import_applications", zero)
    monkeypatch.setattr(importer, "import_tcc_grants", pair)
    monkeypatch.setattr(importer, "import_entitlements", pair)
    monkeypatch.setattr(importer, "import_signed_by_team", zero)
    monkeypatch.setattr(importer, "import_certificate_authorities", triple)
    monkeypatch.setattr(importer, "import_xpc_services", pair)
    monkeypatch.setattr(importer, "import_keychain_items", pair)
    monkeypatch.setattr(importer, "import_mdm_profiles", pair)
    monkeypatch.setattr(importer, "import_local_groups", pair)
    monkeypatch.setattr(importer, "import_launch_items", quad)
    monkeypatch.setattr(importer, "import_remote_access_services", pair)
    monkeypatch.setattr(importer, "import_firewall_status", pair)
    monkeypatch.setattr(importer, "import_login_sessions", pair)
    monkeypatch.setattr(importer, "import_authorization_rights", zero)
    monkeypatch.setattr(importer, "import_authorization_plugins", zero)
    monkeypatch.setattr(importer, "import_system_extensions", zero)
    monkeypatch.setattr(importer, "import_sudoers_rules", pair)
    monkeypatch.setattr(importer, "import_running_processes", zero)
    monkeypatch.setattr(importer, "import_user_details", zero)
    monkeypatch.setattr(importer, "import_file_acls", zero)
    monkeypatch.setattr(importer, "import_computer", zero)
    monkeypatch.setattr(importer, "import_installed_on", zero)
    monkeypatch.setattr(importer, "import_local_to", zero)
    monkeypatch.setattr(importer, "import_bluetooth_devices", pair)
    monkeypatch.setattr(importer, "import_ad_binding", pair)
    monkeypatch.setattr(importer, "import_kerberos_artifacts", quad)
    monkeypatch.setattr(importer, "import_sandbox_profiles", pair)
