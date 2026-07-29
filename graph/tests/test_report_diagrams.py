"""Tests for report_diagrams.py - all pure functions, no Neo4j required."""

from unittest import TestCase

from report_diagrams import (
    format_family_findings_section,
    format_multi_plane_campaign_section,
    format_multi_plane_severity_board,
    format_purple_engagement_matrix,
    format_kill_chain_stage_timeline,
    format_fleet_campaign_dashboard,
    mermaid_attack_path,
    mermaid_family_findings_block,
    mermaid_tcc_pie,
    sanitize_mermaid_id,
)


checks = TestCase()


class TestSanitizeMermaidId:
    def test_strips_dots_and_spaces(self):
        checks.assertEqual("com_apple_foo", sanitize_mermaid_id("com.apple.foo"))

    def test_handles_slashes(self):
        result = sanitize_mermaid_id("/Applications/Foo.app")
        checks.assertNotIn("/", result)
        checks.assertNotIn(".", result)

    def test_empty_string(self):
        result = sanitize_mermaid_id("")
        checks.assertTrue(isinstance(result, str))


class TestMermaidAttackPath:
    def test_two_node_path(self):
        path_result = {
            "node_names": ["attacker_payload", "iTerm2"],
            "rel_types": ["CAN_INJECT_INTO"],
            "path_length": 1,
        }
        diagram = mermaid_attack_path(path_result)
        checks.assertIn("graph LR", diagram)
        checks.assertIn("CAN_INJECT_INTO", diagram)
        checks.assertIn("attacker_payload", diagram)
        checks.assertIn("iTerm2", diagram)

    def test_three_node_path(self):
        path_result = {
            "node_names": ["attacker_payload", "Slack", "Full Disk Access"],
            "rel_types": ["CAN_INJECT_INTO", "HAS_TCC_GRANT"],
            "path_length": 2,
        }
        diagram = mermaid_attack_path(path_result)
        checks.assertIn("graph LR", diagram)
        checks.assertIn("CAN_INJECT_INTO", diagram)
        checks.assertIn("HAS_TCC_GRANT", diagram)

    def test_highlights_tcc_node(self):
        path_result = {
            "node_names": ["attacker_payload", "iTerm2", "Full Disk Access"],
            "rel_types": ["CAN_INJECT_INTO", "HAS_TCC_GRANT"],
            "path_length": 2,
        }
        diagram = mermaid_attack_path(path_result)
        # TCC nodes should be styled red
        checks.assertIn("fill:#ff6666", diagram)

    def test_empty_path_returns_empty(self):
        result = mermaid_attack_path(
            {"node_names": [], "rel_types": [], "path_length": 0}
        )
        checks.assertEqual(result, "")

    def test_mismatched_nodes_rels_is_safe(self):
        # Should not raise, even if len(nodes) != len(rels) + 1
        path_result = {
            "node_names": ["A"],
            "rel_types": [],
            "path_length": 0,
        }
        result = mermaid_attack_path(path_result)
        checks.assertTrue(isinstance(result, str))


class TestMermaidTccPie:
    def test_basic_pie_chart(self):
        rows = [
            {"permission": "Full Disk Access", "total_grants": 5},
            {"permission": "Camera", "total_grants": 3},
            {"permission": "Microphone", "total_grants": 2},
        ]
        diagram = mermaid_tcc_pie(rows)
        checks.assertIn("pie", diagram)
        checks.assertIn("Full Disk Access", diagram)
        checks.assertIn("5", diagram)

    def test_empty_rows(self):
        diagram = mermaid_tcc_pie([])
        checks.assertTrue(isinstance(diagram, str))

    def test_top_n_limiting(self):
        rows = [{"permission": f"Perm{i}", "total_grants": i} for i in range(1, 20)]
        diagram = mermaid_tcc_pie(rows, top_n=10)
        # Should not include all 19 entries
        checks.assertLessEqual(diagram.count('"'), 22)


class TestMermaidFamilyFindings:
    def test_red_blue_styles(self):
        findings = [
            {
                "finding_id": "rootstock.vector.delivery.url_scheme_handler",
                "name": "URL scheme handler",
                "severity": "medium",
                "source": "rootstock-red",
            },
            {
                "finding_id": "harden.launchd_override_depth",
                "name": "Launchd override depth",
                "severity": "high",
                "source": "rootstock-blue",
            },
            {
                "finding_id": "rootstock.vector.persist.browser_extension_dualuse",
                "name": "Browser extension dual-use",
                "severity": "medium",
                "source": "rootstock-red",
            },
            {
                "finding_id": "harden.shortcuts_app_intents",
                "name": "Shortcuts automation",
                "severity": "medium",
                "source": "rootstock-blue",
            },
        ]
        diagram = mermaid_family_findings_block(findings)
        checks.assertIn("flowchart TB", diagram)
        checks.assertIn("fill:#c0392b", diagram)  # red
        checks.assertIn("fill:#2471a3", diagram)  # blue
        checks.assertIn("[R]", diagram)
        checks.assertIn("[B]", diagram)

    def test_empty_findings(self):
        diagram = mermaid_family_findings_block([])
        checks.assertIn("No family findings", diagram)

    def test_format_section_nonempty(self):
        findings = [
            {
                "finding_id": "rootstock.vector.defense.launchd_override_depth",
                "name": "Launchd override depth",
                "severity": "high",
                "source": "rootstock-red",
            },
            {
                "finding_id": "harden.url_scheme_handler",
                "name": "URL scheme harden",
                "severity": "medium",
                "source": "rootstock-blue",
            },
        ]
        section = format_family_findings_section(findings)
        checks.assertIn("Family Red/Blue Findings", section)
        checks.assertIn("rootstock.vector.defense.launchd_override_depth", section)
        checks.assertIn("harden.url_scheme_handler", section)
        checks.assertIn("```mermaid", section)
        checks.assertTrue(len(section) > 100)


class TestMultiPlaneCampaign:
    def test_campaign_section_nonempty(self):
        planes = [
            {
                "id": "webloc",
                "title": "Webloc delivery",
                "stage": "delivery",
                "red_ids": ["rootstock.vector.delivery.webloc_inetloc"],
                "blue_ids": ["webloc_inetloc_delivery"],
            },
            {
                "id": "mail_rules",
                "title": "Mail rules",
                "stage": "persist",
                "red_ids": ["rootstock.vector.persist.mail_rules_automation"],
                "blue_ids": ["mail_rules_automation"],
            },
        ]
        section = format_multi_plane_campaign_section(planes, campaign="Wave-12")
        checks.assertIn("Wave-12 campaign", section)
        checks.assertIn("webloc_inetloc", section)
        checks.assertIn("mail_rules", section)
        checks.assertIn("```mermaid", section)
        checks.assertTrue(len(section) > 80)

    def test_empty_campaign(self):
        section = format_multi_plane_campaign_section([])
        checks.assertIn("No multi-plane themes", section)


class TestMultiPlaneSeverityBoard:
    def test_board_ranks_and_diagrams(self):
        findings = [
            {"finding_id": "rootstock.vector.data.screencapture_privacy", "name": "ScreenCapture", "severity": "high", "source": "rootstock-red"},
            {"finding_id": "harden.homebrew_package_dualuse", "name": "Homebrew", "severity": "medium", "source": "rootstock-blue"},
            {"finding_id": "rootstock.vector.codesign.gk_assessment_history", "name": "GK history", "severity": "low", "source": "rootstock-red"},
        ]
        section = format_multi_plane_severity_board(findings)
        checks.assertIn("Multi-plane severity board", section)
        checks.assertIn("screencapture_privacy", section)
        checks.assertIn("homebrew_package_dualuse", section)
        checks.assertIn("```mermaid", section)
        # high before medium in table order
        hi = section.find("high")
        med = section.find("medium")
        checks.assertTrue(0 <= hi < med)

    def test_empty_board(self):
        checks.assertIn("No findings", format_multi_plane_severity_board([]))


class TestPurpleEngagementMatrix:
    def test_matrix_nonempty(self):
        pairs = [
            {"plane": "Automator", "stage": "delivery", "red_id": "rootstock.vector.delivery.automator_workflow", "blue_id": "automator_workflow"},
            {"plane": "PAM", "stage": "auth", "red_id": "rootstock.vector.auth.pam_auth_module", "blue_id": "pam_auth_module"},
        ]
        section = format_purple_engagement_matrix(pairs)
        checks.assertIn("Purple engagement matrix", section)
        checks.assertIn("automator_workflow", section)
        checks.assertIn("pam_auth_module", section)
        checks.assertIn("```mermaid", section)
        checks.assertTrue(len(section) > 100)

    def test_empty_matrix(self):
        checks.assertIn("No red↔blue pairs", format_purple_engagement_matrix([]))


class TestKillChainStageTimeline:
    def test_timeline_nonempty(self):
        stages = [
            {"stage": "delivery", "label": "Automator/webloc", "red_count": 3, "blue_count": 2},
            {"stage": "collection", "label": "Photos/keychain paths", "red_count": 4, "blue_count": 3},
            {"stage": "lateral", "label": "ARD/VPN dual-use", "red_count": 2, "blue_count": 2},
        ]
        section = format_kill_chain_stage_timeline(stages)
        checks.assertIn("Kill-chain stage timeline", section)
        checks.assertIn("```mermaid", section)
        checks.assertIn("timeline", section)
        checks.assertIn("delivery", section)
        checks.assertIn("collection", section)
        checks.assertTrue(len(section) > 80)

    def test_empty_timeline(self):
        checks.assertIn("No stages", format_kill_chain_stage_timeline([]))


class TestFleetCampaignDashboard:
    def test_dashboard_aggregates(self):
        campaigns = [
            {"name": "Wave-14", "theme_count": 10, "half_pairs": 20, "stages": ["delivery", "auth"], "highlight": "Automator/PAM"},
            {"name": "Wave-15", "theme_count": 10, "half_pairs": 20, "stages": ["collection", "remote"], "highlight": "Photos/ARD"},
            {"name": "Wave-16", "theme_count": 25, "half_pairs": 50, "stages": ["privacy", "media", "mdm"], "highlight": "25 planes"},
        ]
        section = format_fleet_campaign_dashboard(campaigns)
        checks.assertIn("Fleet multi-plane campaign dashboard", section)
        checks.assertIn("Wave-16", section)
        checks.assertIn("50", section)
        checks.assertIn("```mermaid", section)
        checks.assertTrue("45" in section or "themes" in section.lower())
        checks.assertTrue(len(section) > 120)

    def test_empty_fleet(self):
        checks.assertIn("No campaigns", format_fleet_campaign_dashboard([]))
