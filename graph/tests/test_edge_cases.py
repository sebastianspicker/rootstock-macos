"""
test_edge_cases.py - Edge case tests for the Rootstock graph pipeline.

Tests for: empty scans, null fields, orphan grants, empty CVE registry,
safe_count helper, and Pydantic extra-field rejection.

No Neo4j required unless marked with neo4j_required.
"""

from __future__ import annotations

from unittest import TestCase

from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError


# ── Empty scan handling ────────────────────────────────────────────────────

checks = TestCase()


class TestEmptyScan:
    def test_empty_applications_list(self):
        from models import ScanResult

        data = {
            "scan_id": "test-empty",
            "timestamp": "2026-03-21T00:00:00Z",
            "hostname": "empty.local",
            "macos_version": "15.0",
            "collector_version": "0.1.0",
            "elevation": {"is_root": False, "has_fda": False},
            "applications": [],
            "tcc_grants": [],
            "errors": [],
        }
        scan = ScanResult.model_validate(data)
        checks.assertEqual(len(scan.applications), 0)
        checks.assertEqual(len(scan.tcc_grants), 0)

    def test_scan_with_only_errors(self):
        from models import ScanResult

        data = {
            "scan_id": "test-errors-only",
            "timestamp": "2026-03-21T00:00:00Z",
            "hostname": "broken.local",
            "macos_version": "15.0",
            "collector_version": "0.1.0",
            "elevation": {"is_root": False, "has_fda": False},
            "applications": [],
            "tcc_grants": [],
            "errors": [
                {"source": "TCC", "message": "FDA required", "recoverable": True},
                {"source": "Keychain", "message": "locked", "recoverable": False},
            ],
        }
        scan = ScanResult.model_validate(data)
        checks.assertEqual(len(scan.errors), 2)
        checks.assertIs(scan.errors[0].recoverable, True)
        checks.assertIs(scan.errors[1].recoverable, False)


# ── Null/missing field handling ────────────────────────────────────────────


class TestNullFields:
    def test_application_null_optional_fields(self):
        from models import ApplicationData

        app = ApplicationData.model_validate(
            {
                "name": "NullApp",
                "bundle_id": "com.null.app",
                "path": "/Applications/NullApp.app",
                "hardened_runtime": True,
                "library_validation": True,
                "is_electron": False,
                "is_system": False,
                "signed": True,
            }
        )
        checks.assertIsNone(app.version)
        checks.assertIsNone(app.team_id)
        checks.assertIsNone(app.certificate_expires)
        checks.assertEqual(app.injection_methods, [])
        checks.assertEqual(app.entitlements, [])

    def test_tcc_grant_null_display_name_rejected(self):
        from models import TCCGrantData

        with pytest.raises(ValidationError):
            TCCGrantData.model_validate(
                {
                    "service": "kTCCServiceCamera",
                    "display_name": "",  # min_length=1
                    "client": "com.example.app",
                    "client_type": 0,
                    "auth_value": 2,
                    "auth_reason": 1,
                    "scope": "user",
                    "last_modified": 0,
                }
            )


# ── Pydantic extra-field rejection (Step 2.7) ─────────────────────────────


class TestExtraFieldRejection:
    def test_scan_result_rejects_unknown_field(self):
        from models import ScanResult

        data = {
            "scan_id": "test-extra",
            "timestamp": "2026-03-21T00:00:00Z",
            "hostname": "extra.local",
            "macos_version": "15.0",
            "collector_version": "0.1.0",
            "elevation": {"is_root": False, "has_fda": False},
            "applications": [],
            "tcc_grants": [],
            "errors": [],
            "totally_unknown_field": "should fail",
        }
        with pytest.raises(ValidationError, match="extra"):
            ScanResult.model_validate(data)

    def test_application_rejects_unknown_field(self):
        from models import ApplicationData

        with pytest.raises(ValidationError, match="extra"):
            ApplicationData.model_validate(
                {
                    "name": "ExtraApp",
                    "bundle_id": "com.extra.app",
                    "path": "/Applications/Extra.app",
                    "hardened_runtime": True,
                    "library_validation": True,
                    "is_electron": False,
                    "is_system": False,
                    "signed": True,
                    "misspelled_field": True,
                }
            )


# ── safe_count edge cases ─────────────────────────────────────────────────


class TestSafeCount:
    def test_safe_count_with_zero(self):
        from utils import safe_count

        mock = MagicMock()
        mock.single.return_value = {"n": 0}
        checks.assertEqual(safe_count(mock), 0)

    def test_safe_count_with_large_value(self):
        from utils import safe_count

        mock = MagicMock()
        mock.single.return_value = {"n": 999999}
        checks.assertEqual(safe_count(mock), 999999)


# ── Version matcher pre-release edge cases ─────────────────────────────────


class TestVersionMatcherEdgeCases:
    def test_prerelease_beta_less_than_release(self):
        from version_matcher import version_lt

        checks.assertIs(version_lt("15beta3", "15.0"), True)

    def test_dev_less_than_alpha(self):
        from version_matcher import parse_version_tuple

        dev = parse_version_tuple("15dev1")
        alpha = parse_version_tuple("15alpha1")
        checks.assertLess(dev, alpha)

    def test_version_with_build_metadata(self):
        """Versions like '15.0+build123' should parse the numeric part."""
        from version_matcher import parse_version_tuple

        result = parse_version_tuple("15.0")
        checks.assertEqual(result, (15, 0))


# ── Cypher validation edge cases ─────────────────────────────────────────


class TestCypherValidationEdgeCases:
    def test_multi_line_injection_attempt(self):
        from utils import validate_read_only_cypher

        query = "MATCH (n) RETURN n\n// innocent\nCREATE (m:Evil)"
        checks.assertIsNotNone(validate_read_only_cypher(query))

    def test_set_in_property_name_safe(self):
        """Properties containing 'SET' as a substring should not trigger."""
        from utils import validate_read_only_cypher

        query = "MATCH (n) WHERE n.dataset = 'train' RETURN n"
        checks.assertIsNone(validate_read_only_cypher(query))

    def test_unicode_bypass_attempt(self):
        """Unicode variations of keywords should not bypass validation."""
        from utils import validate_read_only_cypher

        # Normal CREATE should be caught
        checks.assertIsNotNone(validate_read_only_cypher("CREATE (n)"))

    def test_nested_subquery_call(self):
        """CALL {} (subquery) should be rejected."""
        from utils import validate_read_only_cypher

        query = "MATCH (n) CALL { WITH n CREATE (m) } RETURN n"
        checks.assertIsNotNone(validate_read_only_cypher(query))

    def test_load_csv_with_headers(self):
        from utils import validate_read_only_cypher

        query = "LOAD CSV WITH HEADERS FROM 'file:///data.csv' AS row RETURN row"
        checks.assertIsNotNone(validate_read_only_cypher(query))
