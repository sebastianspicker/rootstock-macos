"""Tests for report_diagrams.py — all pure functions, no Neo4j required."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from report_diagrams import (
    mermaid_attack_path,
    mermaid_tcc_pie,
    sanitize_mermaid_id,
)


class TestSanitizeMermaidId:
    def test_strips_dots_and_spaces(self):
        assert "com_apple_foo" == sanitize_mermaid_id("com.apple.foo")

    def test_handles_slashes(self):
        result = sanitize_mermaid_id("/Applications/Foo.app")
        assert "/" not in result
        assert "." not in result

    def test_empty_string(self):
        result = sanitize_mermaid_id("")
        assert isinstance(result, str)


class TestMermaidAttackPath:
    def test_two_node_path(self):
        path_result = {
            "node_names": ["attacker_payload", "iTerm2"],
            "rel_types": ["CAN_INJECT_INTO"],
            "path_length": 1,
        }
        diagram = mermaid_attack_path(path_result)
        assert "graph LR" in diagram
        assert "CAN_INJECT_INTO" in diagram
        assert "attacker_payload" in diagram
        assert "iTerm2" in diagram

    def test_three_node_path(self):
        path_result = {
            "node_names": ["attacker_payload", "Slack", "Full Disk Access"],
            "rel_types": ["CAN_INJECT_INTO", "HAS_TCC_GRANT"],
            "path_length": 2,
        }
        diagram = mermaid_attack_path(path_result)
        assert "graph LR" in diagram
        assert "CAN_INJECT_INTO" in diagram
        assert "HAS_TCC_GRANT" in diagram

    def test_highlights_tcc_node(self):
        path_result = {
            "node_names": ["attacker_payload", "iTerm2", "Full Disk Access"],
            "rel_types": ["CAN_INJECT_INTO", "HAS_TCC_GRANT"],
            "path_length": 2,
        }
        diagram = mermaid_attack_path(path_result)
        # TCC nodes should be styled red
        assert "fill:#ff6666" in diagram

    def test_empty_path_returns_empty(self):
        result = mermaid_attack_path({"node_names": [], "rel_types": [], "path_length": 0})
        assert result == ""

    def test_mismatched_nodes_rels_is_safe(self):
        # Should not raise, even if len(nodes) != len(rels) + 1
        path_result = {
            "node_names": ["A"],
            "rel_types": [],
            "path_length": 0,
        }
        result = mermaid_attack_path(path_result)
        assert isinstance(result, str)


class TestMermaidTccPie:
    def test_basic_pie_chart(self):
        rows = [
            {"permission": "Full Disk Access", "total_grants": 5},
            {"permission": "Camera", "total_grants": 3},
            {"permission": "Microphone", "total_grants": 2},
        ]
        diagram = mermaid_tcc_pie(rows)
        assert "pie" in diagram
        assert "Full Disk Access" in diagram
        assert "5" in diagram

    def test_empty_rows(self):
        diagram = mermaid_tcc_pie([])
        assert isinstance(diagram, str)

    def test_top_n_limiting(self):
        rows = [{"permission": f"Perm{i}", "total_grants": i} for i in range(1, 20)]
        diagram = mermaid_tcc_pie(rows, top_n=10)
        # Should not include all 19 entries
        assert diagram.count('"') <= 22  # 10 entries × 2 quotes + some extra
