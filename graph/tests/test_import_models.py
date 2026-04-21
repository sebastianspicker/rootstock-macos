"""
test_import_models.py — Pydantic model validation tests (no Neo4j required).

Usage:
    pytest graph/tests/test_import_models.py -v
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURE_PATH = Path(__file__).parent / "fixture_minimal.json"
TEST_SCAN_ID = "test-00000000-0000-0000-0000-000000000001"


class TestPydanticModels:
    def test_fixture_loads_cleanly(self):
        from models import ScanResult
        data = json.loads(FIXTURE_PATH.read_text())
        scan = ScanResult.model_validate(data)
        assert len(scan.applications) == 3
        assert len(scan.tcc_grants) == 5
        assert len(scan.xpc_services) == 2
        assert len(scan.keychain_acls) == 3
        assert len(scan.mdm_profiles) == 2
        assert len(scan.launch_items) == 3

    def test_entitlement_counts(self):
        from models import ScanResult
        data = json.loads(FIXTURE_PATH.read_text())
        scan = ScanResult.model_validate(data)
        total = sum(len(a.entitlements) for a in scan.applications)
        assert total == 11, f"Expected 11 entitlements, got {total}"

    def test_tcc_grant_allowed_property(self):
        from models import TCCGrantData
        grant_allow = TCCGrantData(
            service="kTCCServiceMicrophone", display_name="Microphone",
            client="com.example.app", client_type=0,
            auth_value=2, auth_reason=1, scope="user", last_modified=0,
        )
        assert grant_allow.allowed is True

        grant_deny = grant_allow.model_copy(update={"auth_value": 0})
        assert grant_deny.allowed is False

        grant_limited = grant_allow.model_copy(update={"auth_value": 3})
        assert grant_limited.allowed is True

    def test_missing_required_field_raises(self):
        from models import ApplicationData
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            ApplicationData.model_validate({"name": "Broken"})  # missing bundle_id etc.

    def test_invalid_category_raises(self):
        from models import EntitlementData
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            EntitlementData.model_validate({
                "name": "com.example.ent", "is_private": False,
                "category": "INVALID_CATEGORY", "is_security_critical": False,
            })

    def test_launch_item_defaults(self):
        from models import LaunchItemData
        item = LaunchItemData.model_validate({
            "label": "com.example.minimal",
            "path": "/Library/LaunchDaemons/com.example.minimal.plist",
            "type": "daemon",
        })
        assert item.program is None
        assert item.user is None
        assert item.run_at_load is False

    def test_launch_item_invalid_type_raises(self):
        from models import LaunchItemData
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            LaunchItemData.model_validate({
                "label": "com.example.bad",
                "path": "/Library/LaunchDaemons/com.example.bad.plist",
                "type": "INVALID",
            })

    def test_xpc_service_defaults(self):
        from models import XPCServiceData
        svc = XPCServiceData.model_validate({
            "label": "com.example.minimal",
            "path": "/Library/LaunchDaemons/com.example.minimal.plist",
            "type": "daemon",
        })
        assert svc.program is None
        assert svc.user is None
        assert svc.run_at_load is False
        assert svc.keep_alive is False
        assert svc.mach_services == []
        assert svc.entitlements == []

    def test_xpc_service_invalid_type_raises(self):
        from models import XPCServiceData
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            XPCServiceData.model_validate({
                "label": "com.example.bad",
                "path": "/Library/LaunchDaemons/com.example.bad.plist",
                "type": "INVALID_TYPE",
            })

    def test_missing_fields_in_application_returns_defaults(self):
        """Fields with defaults should not fail validation."""
        from models import ApplicationData
        app = ApplicationData.model_validate({
            "name": "Minimal", "bundle_id": "com.example.minimal",
            "path": "/Applications/Minimal.app",
            "hardened_runtime": False, "library_validation": False,
            "is_electron": False, "is_system": False, "signed": False,
            # entitlements and injection_methods use default_factory=list
        })
        assert app.entitlements == []
        assert app.injection_methods == []

    def test_keychain_item_defaults(self):
        from models import KeychainItemData
        item = KeychainItemData.model_validate({
            "label": "My Credential",
            "kind": "generic_password",
        })
        assert item.service is None
        assert item.access_group is None
        assert item.trusted_apps == []

    def test_keychain_item_invalid_kind_raises(self):
        from models import KeychainItemData
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            KeychainItemData.model_validate({
                "label": "Bad Item",
                "kind": "INVALID_KIND",
            })

    def test_keychain_item_with_trusted_apps(self):
        from models import KeychainItemData
        item = KeychainItemData.model_validate({
            "label": "SSH Key",
            "kind": "generic_password",
            "service": "OpenSSH",
            "access_group": "TEAMID.com.example",
            "trusted_apps": ["com.example.app", "com.apple.Terminal"],
        })
        assert len(item.trusted_apps) == 2
        assert "com.apple.Terminal" in item.trusted_apps

    def test_mdm_profile_defaults(self):
        from models import MDMProfileData
        profile = MDMProfileData.model_validate({
            "identifier": "com.example.profile",
            "display_name": "Test Profile",
        })
        assert profile.organization is None
        assert profile.install_date is None
        assert profile.tcc_policies == []

    def test_mdm_tcc_policy_fields(self):
        from models import MDMProfileData
        profile = MDMProfileData.model_validate({
            "identifier": "com.example.profile",
            "display_name": "Privacy Profile",
            "tcc_policies": [
                {"service": "SystemPolicyAllFiles", "client_bundle_id": "com.example.app", "allowed": True},
                {"service": "Microphone", "client_bundle_id": "com.example.app", "allowed": False},
            ],
        })
        assert len(profile.tcc_policies) == 2
        fda = next(p for p in profile.tcc_policies if p.service == "SystemPolicyAllFiles")
        assert fda.client_bundle_id == "com.example.app"
        assert fda.allowed is True

    def test_mdm_profile_missing_required_raises(self):
        from models import MDMProfileData
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            MDMProfileData.model_validate({"identifier": "com.example.only-identifier"})  # missing display_name
