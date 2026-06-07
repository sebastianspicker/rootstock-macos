"""
Tests for report.py formatting functions — no Neo4j required.
All tested functions take query result dicts and return Markdown strings.
"""

import sys
import os
import json
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from report import (
    ScanMetadataError,
    get_scan_metadata_from_neo4j,
    get_scan_metadata_from_json,
    main,
    run_all_queries,
)
from report_assembly import assemble_report, markdown_to_html
from report_formatters import (
    format_apple_event_table,
    format_electron_table,
    format_executive_summary,
    format_generic_table,
    format_injectable_fda_table,
    format_no_findings,
    format_private_entitlement_table,
    format_tcc_overview_table,
)
from unittest import TestCase
from unittest.mock import ANY, MagicMock, patch


checks = TestCase()


def assert_report_line_contains(lines, label, value):
    matches = [line for line in lines if label in line and value in line]
    checks.assertTrue(matches)


def assert_report_line_missing(lines, label, value):
    matches = [line for line in lines if label in line and value in line]
    checks.assertFalse(matches)


def injectable_fda_query_results():
    return {
        "01-injectable-fda-apps.cypher": [
            {
                "app_name": "München <Agent>",
                "bundle_id": "com.example.agent",
                "team_id": "TEAMID",
                "injection_methods": ["missing_library_validation"],
                "method_count": 1,
                "path": "/Applications/Agent.app",
            }
        ],
        "07-tcc-grant-overview.cypher": [
            {
                "permission": "Full Disk Access",
                "service": "kTCCServiceSystemPolicyAllFiles",
                "allowed_count": 1,
                "denied_count": 0,
                "total_grants": 1,
            }
        ],
    }


def assert_injectable_report_order(report):
    critical_heading = "## Critical Findings: Injectable Apps with Privileged TCC Grants"
    electron_heading = "## High Findings: Electron TCC Inheritance"

    checks.assertLess(report.index("## Executive Summary"), report.index(critical_heading))
    checks.assertLess(report.index(critical_heading), report.index(electron_heading))


def injectable_report_sections(report):
    critical_heading = "## Critical Findings: Injectable Apps with Privileged TCC Grants"
    electron_heading = "## High Findings: Electron TCC Inheritance"
    apple_event_heading = "## High Findings: Apple Event TCC Cascade"

    return (
        report[report.index(critical_heading) : report.index(electron_heading)],
        report[report.index(electron_heading) : report.index(apple_event_heading)],
    )


class TestFormatNoFindings:
    def test_returns_markdown_string(self):
        result = format_no_findings()
        checks.assertTrue(isinstance(result, str))
        checks.assertIn("No findings", result)


class TestHtmlReportEscaping:
    def test_query_values_are_escaped_before_html_conversion(self):
        table = format_generic_table([{"app": '<script>alert("x")</script>'}])
        html = markdown_to_html(table)

        checks.assertNotIn("<script>", html)
        checks.assertTrue("&lt;script&gt;" in html or "&amp;lt;script&amp;gt;" in html)


class TestReportAssembly:
    def _metadata(self):
        return {
            "hostname": "fixture-host",
            "macos_version": "14.5",
            "timestamp": "2026-04-17T00:00:00Z",
            "scan_id": "fixture-scan",
            "collector_version": "0.2.0",
            "is_root": False,
            "has_fda": True,
            "app_count": 1,
            "tcc_grant_count": 1,
            "entitlement_count": 1,
        }

    def test_enrichment_failure_is_reported(self, monkeypatch):
        def fail_enrichment():
            raise RuntimeError("fixture enrichment failure")

        monkeypatch.setitem(
            sys.modules,
            "cve_enrichment",
            SimpleNamespace(enrich_registry=fail_enrichment),
        )
        monkeypatch.setattr("report_assembly.discover_queries", lambda: [])

        report = assemble_report({}, {"hostname": "fixture-host"})

        checks.assertIn("### Vulnerability Intelligence", report)
        checks.assertIn("CVE enrichment unavailable", report)
        checks.assertIn("fixture enrichment failure", report)

    def test_missing_posture_metadata_renders_unknown_not_false(self, monkeypatch):
        monkeypatch.setattr("report_assembly.discover_queries", lambda: [])

        report = assemble_report(
            {}, {"hostname": "fixture-host", "icloud_signed_in": True}
        )
        lines = report.splitlines()

        assert_report_line_contains(lines, "Elevation", "unknown")
        assert_report_line_missing(lines, "Elevation", "user")
        assert_report_line_contains(lines, "Full Disk Access (collector)", "unknown")
        assert_report_line_contains(lines, "iCloud Drive", "unknown")
        assert_report_line_contains(lines, "iCloud Keychain", "unknown")

    def test_injectable_fda_finding_reaches_summary_detail_and_recommendations(
        self, monkeypatch
    ):
        monkeypatch.setitem(
            sys.modules,
            "cve_enrichment",
            SimpleNamespace(enrich_registry=lambda: {}),
        )

        report = assemble_report(injectable_fda_query_results(), self._metadata())
        assert_injectable_report_order(report)
        critical_section, electron_section = injectable_report_sections(report)

        checks.assertIn("**Overall Risk: CRITICAL**", report)
        checks.assertIn("München &lt;Agent&gt;", critical_section)
        checks.assertIn("missing_library_validation", critical_section)
        checks.assertNotIn("München &lt;Agent&gt;", electron_section)
        checks.assertNotIn("München <Agent>", report)
        checks.assertIn("Full Disk Access and is injectable", report)
        checks.assertIn(
            "### Injectable Applications with Privileged TCC Grants", report
        )
        checks.assertIn("01-injectable-fda-apps.cypher", report)

    def test_empty_report_keeps_low_risk_and_no_injectable_recommendation(
        self, monkeypatch
    ):
        monkeypatch.setitem(
            sys.modules,
            "cve_enrichment",
            SimpleNamespace(enrich_registry=lambda: {}),
        )

        report = assemble_report({}, self._metadata())

        checks.assertIn("**Overall Risk: LOW**", report)
        checks.assertIn("_No attack paths discovered._", report)
        checks.assertIn(
            "## Critical Findings: Injectable Apps with Privileged TCC Grants", report
        )
        checks.assertIn("_No findings in this category._", report)
        checks.assertNotIn(
            "### Injectable Applications with Privileged TCC Grants", report
        )

    def test_file_acl_query_drives_vulnerability_context_and_recommendation(
        self, monkeypatch
    ):
        monkeypatch.setitem(
            sys.modules,
            "cve_enrichment",
            SimpleNamespace(enrich_registry=lambda: {}),
        )
        query_results = {
            "48-file-acl-write-paths.cypher": [
                {
                    "path": "/Library/Application Support/com.example/TCC.db",
                    "principal": "staff",
                    "access": "write",
                }
            ],
        }

        report = assemble_report(query_results, self._metadata())

        checks.assertIn("## Top Vulnerabilities & ATT&CK Mapping", report)
        checks.assertIn("file_acl_escalation", report)
        checks.assertIn("### File ACL Escalation Mitigation", report)


class TestFormatInjectableFdaTable:
    def test_basic_table(self):
        rows = [
            {
                "app_name": "iTerm2",
                "bundle_id": "com.googlecode.iterm2",
                "team_id": "H7V7XYVQ7D",
                "injection_methods": ["missing_library_validation"],
                "method_count": 1,
                "path": "/Applications/iTerm.app",
            }
        ]
        result = format_injectable_fda_table(rows)
        checks.assertIn("iTerm2", result)
        checks.assertIn("missing_library_validation", result)
        checks.assertIn("H7V7XYVQ7D", result)

    def test_empty_returns_no_findings(self):
        result = format_injectable_fda_table([])
        checks.assertIn("No findings", result)

    def test_multiple_injection_methods_joined(self):
        rows = [
            {
                "app_name": "Slack",
                "bundle_id": "com.tinyspeck.slackmacgap",
                "team_id": "BQR82RBBHL",
                "injection_methods": ["missing_library_validation", "electron_env_var"],
                "method_count": 2,
                "path": "/Applications/Slack.app",
            }
        ]
        result = format_injectable_fda_table(rows)
        checks.assertIn("missing_library_validation", result)
        checks.assertIn("electron_env_var", result)


class TestFormatElectronTable:
    def test_basic_table(self):
        rows = [
            {
                "app_name": "Slack",
                "bundle_id": "com.tinyspeck.slackmacgap",
                "inherited_permissions": ["Full Disk Access", "Microphone"],
                "permission_count": 2,
            }
        ]
        result = format_electron_table(rows)
        checks.assertIn("Slack", result)
        checks.assertIn("Full Disk Access", result)

    def test_empty_returns_no_findings(self):
        result = format_electron_table([])
        checks.assertIn("No findings", result)


class TestFormatAppleEventTable:
    def test_basic_table(self):
        rows = [
            {
                "source_app": "Terminal",
                "target_app": "Finder",
                "permission_gained": "Full Disk Access",
            }
        ]
        result = format_apple_event_table(rows)
        checks.assertIn("Terminal", result)
        checks.assertIn("Finder", result)
        checks.assertIn("Full Disk Access", result)

    def test_empty_returns_no_findings(self):
        result = format_apple_event_table([])
        checks.assertIn("No findings", result)


class TestFormatTccOverviewTable:
    def test_basic_table(self):
        rows = [
            {
                "permission": "Full Disk Access",
                "service": "kTCCServiceSystemPolicyAllFiles",
                "allowed_count": 3,
                "denied_count": 0,
                "total_grants": 3,
            },
            {
                "permission": "Camera",
                "service": "kTCCServiceCamera",
                "allowed_count": 5,
                "denied_count": 1,
                "total_grants": 6,
            },
        ]
        result = format_tcc_overview_table(rows)
        checks.assertIn("Full Disk Access", result)
        checks.assertIn("Camera", result)

    def test_empty_returns_no_findings(self):
        result = format_tcc_overview_table([])
        checks.assertIn("No findings", result)


class TestFormatPrivateEntitlementTable:
    def test_basic_table(self):
        rows = [
            {
                "app_name": "Slack",
                "bundle_id": "com.tinyspeck.slackmacgap",
                "private_entitlements": ["com.apple.private.tcc.allow"],
                "is_injectable": True,
            }
        ]
        result = format_private_entitlement_table(rows)
        checks.assertIn("Slack", result)
        checks.assertIn("com.apple.private.tcc.allow", result)
        checks.assertIn("Yes", result)

    def test_empty_returns_no_findings(self):
        result = format_private_entitlement_table([])
        checks.assertIn("No findings", result)


class TestFormatExecutiveSummary:
    def test_counts_reflected(self):
        result = format_executive_summary(
            critical_count=3,
            high_count=7,
            top_paths=[
                "iTerm2 has Full Disk Access and is injectable via missing library validation",
                "Slack inherits Full Disk Access via ELECTRON_RUN_AS_NODE",
            ],
        )
        checks.assertIn("3", result)
        checks.assertIn("7", result)
        checks.assertIn("iTerm2", result)

    def test_zero_findings(self):
        result = format_executive_summary(critical_count=0, high_count=0, top_paths=[])
        checks.assertIn("0", result)


class TestReportMetadata:
    def test_metadata_prefers_computer_node(self):
        driver = MagicMock()
        session_cm = driver.session.return_value.__enter__.return_value
        session_cm.run.side_effect = [
            MagicMock(
                single=lambda: {
                    "app_count": 2,
                    "tcc_grant_count": 3,
                    "entitlement_count": 4,
                }
            ),
            MagicMock(
                single=lambda: {
                    "scan_id": "scan-1",
                    "hostname": "host-a",
                    "macos_version": "14.5",
                    "collector_version": "0.2.0",
                    "timestamp": "2026-04-17T00:00:00Z",
                    "is_root": True,
                    "has_fda": True,
                }
            ),
        ]

        metadata = get_scan_metadata_from_neo4j(driver)

        checks.assertEqual(metadata["scan_id"], "scan-1")
        checks.assertEqual(metadata["hostname"], "host-a")
        checks.assertEqual(metadata["collector_version"], "0.2.0")
        checks.assertIs(metadata["has_fda"], True)

    def test_json_metadata_preserves_missing_elevation_as_unknown(self, tmp_path):
        scan_json = tmp_path / "scan.json"
        scan_json.write_text(
            json.dumps(
                {
                    "scan_id": "scan-unknown",
                    "hostname": "host-a",
                    "macos_version": "14.5",
                    "collector_version": "0.2.0",
                    "timestamp": "2026-04-17T00:00:00Z",
                    "elevation": {},
                }
            ),
            encoding="utf-8",
        )

        metadata = get_scan_metadata_from_json(scan_json)

        checks.assertIsNone(metadata["is_root"])
        checks.assertIsNone(metadata["has_fda"])

    def test_json_metadata_read_error_raises_typed_exception(self, tmp_path):
        missing_scan = tmp_path / "missing-scan.json"

        with pytest.raises(ScanMetadataError, match="Cannot read scan metadata"):
            get_scan_metadata_from_json(missing_scan)


class TestReportQueries:
    def test_parameterized_queries_receive_app_name_default(self, monkeypatch):
        session = MagicMock()
        driver = MagicMock()
        driver.session.return_value.__enter__.return_value = session
        monkeypatch.setattr(
            "report.discover_queries",
            lambda: [
                {
                    "filename": "22-trust-boundary-map.cypher",
                    "cypher": "MATCH (a) WHERE $app_name IS NULL RETURN a",
                    "parameters": "$app_name",
                }
            ],
        )

        with patch("report.run_query", return_value=[]) as run_query_mock:
            results = run_all_queries(driver)

        checks.assertEqual(results["22-trust-boundary-map.cypher"], [])
        run_query_mock.assert_called_once_with(
            session,
            "MATCH (a) WHERE $app_name IS NULL RETURN a",
            ANY,
        )
        params = run_query_mock.call_args.args[2]
        checks.assertIn("app_name", params)
        checks.assertIsNone(params["app_name"])


class TestReportCli:
    def test_main_uses_shared_connection_helper(self, tmp_path, monkeypatch):
        output = tmp_path / "report.md"
        fake_driver = MagicMock()
        monkeypatch.setattr("sys.argv", ["report.py", "--output", str(output)])

        with (
            patch("report.connect_from_args", return_value=fake_driver) as connect_mock,
            patch(
                "report.get_scan_metadata_from_neo4j", return_value={"hostname": "host"}
            ),
            patch("report.run_all_queries", return_value={}),
            patch("report.assemble_report", return_value="# report"),
        ):
            exit_code = main()

        checks.assertEqual(exit_code, 0)
        connect_mock.assert_called_once()
        checks.assertEqual(output.read_text(), "# report")

    def test_main_fails_when_scan_metadata_cannot_be_read(self, tmp_path, monkeypatch):
        output = tmp_path / "report.md"
        missing_scan = tmp_path / "missing-scan.json"
        fake_driver = MagicMock()
        monkeypatch.setattr(
            "sys.argv",
            ["report.py", "--output", str(output), "--scan-json", str(missing_scan)],
        )

        with (
            patch("report.connect_from_args", return_value=fake_driver),
            patch("report.run_all_queries") as run_queries_mock,
            patch("report.assemble_report") as assemble_mock,
        ):
            exit_code = main()

        checks.assertEqual(exit_code, 1)
        fake_driver.close.assert_called_once()
        run_queries_mock.assert_not_called()
        assemble_mock.assert_not_called()
        checks.assertFalse(output.exists())

    def test_main_fails_when_neo4j_metadata_query_reports_uncertainty(
        self, tmp_path, monkeypatch
    ):
        output = tmp_path / "report.md"
        fake_driver = MagicMock()
        monkeypatch.setattr("sys.argv", ["report.py", "--output", str(output)])

        with (
            patch("report.connect_from_args", return_value=fake_driver),
            patch(
                "report.get_scan_metadata_from_neo4j",
                return_value={"_metadata_errors": ["metadata counts: boom"]},
            ),
            patch("report.run_all_queries") as run_queries_mock,
            patch("report.assemble_report") as assemble_mock,
        ):
            exit_code = main()

        checks.assertEqual(exit_code, 1)
        fake_driver.close.assert_called_once()
        run_queries_mock.assert_not_called()
        assemble_mock.assert_not_called()
        checks.assertFalse(output.exists())

    def test_main_fails_when_any_query_fails(self, tmp_path, monkeypatch):
        output = tmp_path / "report.md"
        fake_driver = MagicMock()
        monkeypatch.setattr("sys.argv", ["report.py", "--output", str(output)])

        with (
            patch("report.connect_from_args", return_value=fake_driver),
            patch(
                "report.get_scan_metadata_from_neo4j", return_value={"hostname": "host"}
            ),
            patch(
                "report.run_all_queries",
                return_value={"01-injectable-fda-apps.cypher": "Query failed: boom"},
            ),
            patch("report.assemble_report") as assemble_mock,
        ):
            exit_code = main()

        checks.assertEqual(exit_code, 1)
        fake_driver.close.assert_called_once()
        assemble_mock.assert_not_called()
        checks.assertFalse(output.exists())
