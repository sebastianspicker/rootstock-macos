"""
test_import_models.py - Pydantic model validation tests (no Neo4j required).

Usage:
    pytest graph/tests/test_import_models.py -v
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock

import pytest

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "minimal_scan.json"
TEST_SCAN_ID = "test-00000000-0000-0000-0000-000000000001"


checks = TestCase()


class TestPydanticModels:
    def test_fixture_loads_cleanly(self):
        from models import ScanResult

        data = json.loads(FIXTURE_PATH.read_text())
        scan = ScanResult.model_validate(data)
        checks.assertEqual(len(scan.applications), 3)
        checks.assertEqual(len(scan.tcc_grants), 5)
        checks.assertEqual(len(scan.xpc_services), 2)
        checks.assertEqual(len(scan.keychain_acls), 3)
        checks.assertEqual(len(scan.mdm_profiles), 2)
        checks.assertEqual(len(scan.launch_items), 3)

    def test_entitlement_counts(self):
        from models import ScanResult

        data = json.loads(FIXTURE_PATH.read_text())
        scan = ScanResult.model_validate(data)
        total = sum(len(a.entitlements) for a in scan.applications)
        checks.assertEqual(total, 11, f"Expected 11 entitlements, got {total}")

    def test_tcc_grant_allowed_property(self):
        from models import TCCGrantData

        grant_allow = TCCGrantData(
            service="kTCCServiceMicrophone",
            display_name="Microphone",
            client="com.example.app",
            client_type=0,
            auth_value=2,
            auth_reason=1,
            scope="user",
            last_modified=0,
        )
        checks.assertIs(grant_allow.allowed, True)

        grant_deny = grant_allow.model_copy(update={"auth_value": 0})
        checks.assertIs(grant_deny.allowed, False)

        grant_limited = grant_allow.model_copy(update={"auth_value": 3})
        checks.assertIs(grant_limited.allowed, True)

    def test_missing_required_field_raises(self):
        from models import ApplicationData
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            ApplicationData.model_validate({"name": "Broken"})  # missing bundle_id etc.

    def test_invalid_category_raises(self):
        from models import EntitlementData
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            EntitlementData.model_validate(
                {
                    "name": "com.example.ent",
                    "is_private": False,
                    "category": "INVALID_CATEGORY",
                    "is_security_critical": False,
                }
            )

    def test_launch_item_defaults(self):
        from models import LaunchItemData

        item = LaunchItemData.model_validate(
            {
                "label": "com.example.minimal",
                "path": "/Library/LaunchDaemons/com.example.minimal.plist",
                "type": "daemon",
            }
        )
        checks.assertIsNone(item.program)
        checks.assertIsNone(item.user)
        checks.assertIs(item.run_at_load, False)

    def test_launch_item_invalid_type_raises(self):
        from models import LaunchItemData
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            LaunchItemData.model_validate(
                {
                    "label": "com.example.bad",
                    "path": "/Library/LaunchDaemons/com.example.bad.plist",
                    "type": "INVALID",
                }
            )

    def test_xpc_service_defaults(self):
        from models import XPCServiceData

        svc = XPCServiceData.model_validate(
            {
                "label": "com.example.minimal",
                "path": "/Library/LaunchDaemons/com.example.minimal.plist",
                "type": "daemon",
            }
        )
        checks.assertIsNone(svc.program)
        checks.assertIsNone(svc.user)
        checks.assertIs(svc.run_at_load, False)
        checks.assertIs(svc.keep_alive, False)
        checks.assertEqual(svc.mach_services, [])
        checks.assertEqual(svc.entitlements, [])

    def test_xpc_service_invalid_type_raises(self):
        from models import XPCServiceData
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            XPCServiceData.model_validate(
                {
                    "label": "com.example.bad",
                    "path": "/Library/LaunchDaemons/com.example.bad.plist",
                    "type": "INVALID_TYPE",
                }
            )

    def test_missing_fields_in_application_returns_defaults(self):
        """Fields with defaults should not fail validation."""
        from models import ApplicationData

        app = ApplicationData.model_validate(
            {
                "name": "Minimal",
                "bundle_id": "com.example.minimal",
                "path": "/Applications/Minimal.app",
                "hardened_runtime": False,
                "library_validation": False,
                "is_electron": False,
                "is_system": False,
                "signed": False,
                # entitlements and injection_methods use default_factory=list
            }
        )
        checks.assertEqual(app.entitlements, [])
        checks.assertEqual(app.injection_methods, [])

    def test_code_signing_analysis_error_keeps_signing_posture_unknown(self):
        from import_nodes_core import import_applications
        from models import ApplicationData

        app = ApplicationData.model_validate(
            {
                "name": "Unanalyzable",
                "bundle_id": "com.example.unknown",
                "path": "/Applications/Unknown.app",
                "is_electron": False,
                "is_system": False,
                "code_signing_analysis_error": True,
                "injection_methods": [],
            }
        )

        checks.assertIsNone(app.signed)
        checks.assertIsNone(app.hardened_runtime)
        checks.assertIsNone(app.library_validation)
        checks.assertIs(app.code_signing_analysis_error, True)
        checks.assertEqual(app.injection_methods, [])

        session = MagicMock()
        imported = import_applications(session, [app], TEST_SCAN_ID)
        record = session.run.call_args.kwargs["records"][0]

        checks.assertEqual(imported, 1)
        checks.assertIsNone(record["signed"])
        checks.assertIsNone(record["hardened_runtime"])
        checks.assertIsNone(record["library_validation"])
        checks.assertIs(record["code_signing_analysis_error"], True)
        checks.assertEqual(record["injection_methods"], [])

    def test_entitlement_extraction_error_survives_model_and_import_record(self):
        from import_nodes_core import import_applications
        from models import ApplicationData

        app = ApplicationData.model_validate(
            {
                "name": "Unreadable Entitlements",
                "bundle_id": "com.example.entitlements.unknown",
                "path": "/Applications/EntitlementsUnknown.app",
                "is_electron": False,
                "is_system": False,
                "entitlements_available": False,
                "entitlement_extraction_error": "codesign failed",
                "entitlements": [],
            }
        )

        checks.assertIs(app.entitlements_available, False)
        checks.assertEqual(app.entitlement_extraction_error, "codesign failed")
        checks.assertEqual(app.entitlements, [])

        session = MagicMock()
        imported = import_applications(session, [app], TEST_SCAN_ID)
        record = session.run.call_args.kwargs["records"][0]

        checks.assertEqual(imported, 1)
        checks.assertIs(record["entitlements_available"], False)
        checks.assertEqual(record["entitlement_extraction_error"], "codesign failed")

    def test_firewall_rule_unknown_state_survives_model_and_import_record(self):
        from import_nodes_security import import_firewall_status
        from models import FirewallStatusData

        status = FirewallStatusData.model_validate(
            {
                "enabled": None,
                "stealth_mode": None,
                "allow_signed": None,
                "allow_built_in": None,
                "app_rules": [
                    {"bundle_id": "com.example.firewall", "allow_incoming": None},
                ],
            }
        )

        checks.assertIsNone(status.app_rules[0].allow_incoming)

        result = MagicMock()
        result.single.return_value = {"n": 1}
        session = MagicMock()
        session.run.return_value = result

        imported = import_firewall_status(session, [status], TEST_SCAN_ID)
        rule_record = session.run.call_args_list[1].kwargs["records"][0]

        checks.assertEqual(imported, (1, 1))
        checks.assertIsNone(rule_record["allow_incoming"])

    def test_keychain_item_defaults(self):
        from models import KeychainItemData

        item = KeychainItemData.model_validate(
            {
                "label": "My Credential",
                "kind": "generic_password",
            }
        )
        checks.assertIsNone(item.service)
        checks.assertIsNone(item.access_group)
        checks.assertEqual(item.trusted_apps, [])

    def test_keychain_item_invalid_kind_raises(self):
        from models import KeychainItemData
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            KeychainItemData.model_validate(
                {
                    "label": "Bad Item",
                    "kind": "INVALID_KIND",
                }
            )

    def test_keychain_item_with_trusted_apps(self):
        from models import KeychainItemData

        item = KeychainItemData.model_validate(
            {
                "label": "SSH Key",
                "kind": "generic_password",
                "service": "OpenSSH",
                "access_group": "TEAMID.com.example",
                "trusted_apps": ["com.example.app", "com.apple.Terminal"],
            }
        )
        checks.assertEqual(len(item.trusted_apps), 2)
        checks.assertIn("com.apple.Terminal", item.trusted_apps)

    def test_mdm_profile_defaults(self):
        from models import MDMProfileData

        profile = MDMProfileData.model_validate(
            {
                "identifier": "com.example.profile",
                "display_name": "Test Profile",
            }
        )
        checks.assertIsNone(profile.organization)
        checks.assertIsNone(profile.install_date)
        checks.assertEqual(profile.tcc_policies, [])

    def test_mdm_tcc_policy_fields(self):
        from models import MDMProfileData

        profile = MDMProfileData.model_validate(
            {
                "identifier": "com.example.profile",
                "display_name": "Privacy Profile",
                "tcc_policies": [
                    {
                        "service": "SystemPolicyAllFiles",
                        "client_bundle_id": "com.example.app",
                        "allowed": True,
                    },
                    {
                        "service": "Microphone",
                        "client_bundle_id": "com.example.app",
                        "allowed": False,
                    },
                ],
            }
        )
        checks.assertEqual(len(profile.tcc_policies), 2)
        fda = next(
            p for p in profile.tcc_policies if p.service == "SystemPolicyAllFiles"
        )
        checks.assertEqual(fda.client_bundle_id, "com.example.app")
        checks.assertIs(fda.allowed, True)

    def test_mdm_profile_missing_required_raises(self):
        from models import MDMProfileData
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            MDMProfileData.model_validate(
                {"identifier": "com.example.only-identifier"}
            )  # missing display_name
