"""
Tests for report.py formatting functions — no Neo4j required.
All tested functions take query result dicts and return Markdown strings.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from report import (
    format_injectable_fda_table,
    format_electron_table,
    format_apple_event_table,
    format_tcc_overview_table,
    format_private_entitlement_table,
    format_executive_summary,
    format_no_findings,
    get_scan_metadata_from_neo4j,
    main,
)
from unittest.mock import MagicMock, patch


class TestFormatNoFindings:
    def test_returns_markdown_string(self):
        result = format_no_findings()
        assert isinstance(result, str)
        assert "No findings" in result


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
        assert "iTerm2" in result
        assert "missing_library_validation" in result
        assert "H7V7XYVQ7D" in result

    def test_empty_returns_no_findings(self):
        result = format_injectable_fda_table([])
        assert "No findings" in result

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
        assert "missing_library_validation" in result
        assert "electron_env_var" in result


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
        assert "Slack" in result
        assert "Full Disk Access" in result

    def test_empty_returns_no_findings(self):
        result = format_electron_table([])
        assert "No findings" in result


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
        assert "Terminal" in result
        assert "Finder" in result
        assert "Full Disk Access" in result

    def test_empty_returns_no_findings(self):
        result = format_apple_event_table([])
        assert "No findings" in result


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
        assert "Full Disk Access" in result
        assert "Camera" in result

    def test_empty_returns_no_findings(self):
        result = format_tcc_overview_table([])
        assert "No findings" in result


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
        assert "Slack" in result
        assert "com.apple.private.tcc.allow" in result

    def test_empty_returns_no_findings(self):
        result = format_private_entitlement_table([])
        assert "No findings" in result


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
        assert "3" in result
        assert "7" in result
        assert "iTerm2" in result

    def test_zero_findings(self):
        result = format_executive_summary(critical_count=0, high_count=0, top_paths=[])
        assert "0" in result


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

        assert metadata["scan_id"] == "scan-1"
        assert metadata["hostname"] == "host-a"
        assert metadata["collector_version"] == "0.2.0"
        assert metadata["has_fda"] is True


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

        assert exit_code == 0
        connect_mock.assert_called_once()
        assert output.read_text() == "# report"
