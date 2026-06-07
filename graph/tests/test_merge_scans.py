from __future__ import annotations

from unittest import TestCase

import json
from pathlib import Path

import merge_scans
from models import ScanResult


FIXTURE_PATH = Path(__file__).parent / "fixture_minimal.json"


def _load_scan() -> ScanResult:
    data = json.loads(FIXTURE_PATH.read_text())
    data["scan_id"] = "test-merge-scan"
    return ScanResult.model_validate(data)


checks = TestCase()


def test_import_scan_preserves_import_order_and_summary(monkeypatch, capsys):
    scan = _load_scan()
    calls: list[str] = []

    def recorder(name: str, return_value=None):
        def _record(*_args, **_kwargs):
            calls.append(name)
            return return_value

        return _record

    _patch_core_importers(monkeypatch, recorder)
    _patch_security_importers(monkeypatch, recorder)
    _patch_host_importers(monkeypatch, recorder)

    merge_scans.import_scan(object(), scan)

    checks.assertEqual(calls[:3], ["computer", "apps", "tcc"])
    checks.assertEqual(calls[-3:], ["bluetooth", "installed_on", "local_to"])
    checks.assertIn(
        "3 apps, 2 grants, 4 INSTALLED_ON, 5 LOCAL_TO", capsys.readouterr().out
    )


def _patch_core_importers(monkeypatch, recorder) -> None:
    monkeypatch.setattr(merge_scans, "import_computer", recorder("computer"))
    monkeypatch.setattr(merge_scans, "import_applications", recorder("apps", 3))
    monkeypatch.setattr(merge_scans, "import_tcc_grants", recorder("tcc", (2, 0)))
    monkeypatch.setattr(merge_scans, "import_entitlements", recorder("entitlements"))
    monkeypatch.setattr(merge_scans, "import_signed_by_team", recorder("teams"))
    monkeypatch.setattr(
        merge_scans, "import_certificate_authorities", recorder("cert_authorities")
    )
    monkeypatch.setattr(merge_scans, "import_xpc_services", recorder("xpc"))
    monkeypatch.setattr(merge_scans, "import_keychain_items", recorder("keychain"))
    monkeypatch.setattr(merge_scans, "import_mdm_profiles", recorder("mdm"))


def _patch_security_importers(monkeypatch, recorder) -> None:
    monkeypatch.setattr(merge_scans, "import_launch_items", recorder("launch_items"))
    monkeypatch.setattr(merge_scans, "import_local_groups", recorder("local_groups"))
    monkeypatch.setattr(
        merge_scans, "import_remote_access_services", recorder("remote_access")
    )
    monkeypatch.setattr(merge_scans, "import_firewall_status", recorder("firewall"))
    monkeypatch.setattr(merge_scans, "import_login_sessions", recorder("logins"))
    monkeypatch.setattr(
        merge_scans, "import_authorization_rights", recorder("auth_rights")
    )
    monkeypatch.setattr(
        merge_scans, "import_authorization_plugins", recorder("auth_plugins")
    )
    monkeypatch.setattr(
        merge_scans, "import_system_extensions", recorder("system_extensions")
    )
    monkeypatch.setattr(merge_scans, "import_sudoers_rules", recorder("sudoers"))
    monkeypatch.setattr(merge_scans, "import_running_processes", recorder("processes"))
    monkeypatch.setattr(merge_scans, "import_user_details", recorder("users"))
    monkeypatch.setattr(merge_scans, "import_file_acls", recorder("file_acls"))


def _patch_host_importers(monkeypatch, recorder) -> None:
    monkeypatch.setattr(merge_scans, "import_ad_binding", recorder("ad_binding"))
    monkeypatch.setattr(merge_scans, "import_kerberos_artifacts", recorder("kerberos"))
    monkeypatch.setattr(merge_scans, "import_sandbox_profiles", recorder("sandbox"))
    monkeypatch.setattr(merge_scans, "import_bluetooth_devices", recorder("bluetooth"))
    monkeypatch.setattr(merge_scans, "import_installed_on", recorder("installed_on", 4))
    monkeypatch.setattr(merge_scans, "import_local_to", recorder("local_to", 5))
