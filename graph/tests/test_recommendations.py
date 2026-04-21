"""
test_recommendations.py — Tests for graph-native Recommendation nodes.

Tests infer_recommendations.py — Recommendation node creation,
HAS_RECOMMENDATION edges, and MITIGATES edges.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from infer_recommendations import _RECOMMENDATIONS, infer


# ── Unit tests ───────────────────────────────────────────────────────────────


class TestRecommendationDefinitions:
    def test_recommendations_exist(self):
        assert len(_RECOMMENDATIONS) > 10

    def test_each_recommendation_has_required_fields(self):
        """Each recommendation should be a 6-tuple with correct types."""
        for rec in _RECOMMENDATIONS:
            assert len(rec) == 6
            key, category, text, priority, technique_ids, condition = rec
            assert isinstance(key, str) and len(key) > 0
            assert isinstance(category, str) and len(category) > 0
            assert isinstance(text, str) and len(text) > 0
            assert priority in ("critical", "high", "medium", "low")
            assert isinstance(technique_ids, list)
            assert isinstance(condition, str) and len(condition.strip()) > 0

    def test_unique_keys(self):
        """Recommendation keys should be unique."""
        keys = [rec[0] for rec in _RECOMMENDATIONS]
        assert len(keys) == len(set(keys)), (
            f"Duplicate keys: {[k for k in keys if keys.count(k) > 1]}"
        )

    def test_technique_ids_are_valid_format(self):
        """Technique IDs should match ATT&CK format (T#### or T####.###)."""
        import re

        for rec in _RECOMMENDATIONS:
            for tid in rec[4]:
                assert re.match(r"T\d{4}(\.\d{3})?$", tid), (
                    f"Invalid technique ID: {tid}"
                )

    def test_file_acl_recommendation_uses_host_scoped_user_path(self):
        recommendation = next(
            rec for rec in _RECOMMENDATIONS if rec[0] == "audit_file_acls"
        )
        assert "LOCAL_TO" in recommendation[5]
        assert "CAN_WRITE" in recommendation[5]

    def test_mdm_recommendation_uses_current_import_relationship(self):
        recommendation = next(
            rec for rec in _RECOMMENDATIONS if rec[0] == "review_mdm_pppc"
        )
        assert "CONFIGURES" in recommendation[5]
        assert "MDM_OVERGRANT" not in recommendation[5]


class TestInferFunction:
    def test_infer_creates_recommendation_nodes(self):
        """infer() should call MERGE for each recommendation."""
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.single.return_value = {"n": 0}
        mock_session.run.return_value = mock_result

        count = infer(mock_session)
        assert isinstance(count, int)

        # Check that MERGE was called with Recommendation
        merge_calls = [
            c
            for c in mock_session.run.call_args_list
            if "MERGE" in c[0][0] and "Recommendation" in c[0][0]
        ]
        assert len(merge_calls) >= len(_RECOMMENDATIONS)

    def test_infer_returns_edge_count(self):
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.single.return_value = {"n": 5}
        mock_session.run.return_value = mock_result

        count = infer(mock_session)
        assert isinstance(count, int)


# ── Integration tests (require Neo4j) ────────────────────────────────────


class TestRecommendationIntegration:
    @pytest.fixture(autouse=True)
    def setup(self, neo4j_driver):
        self.driver = neo4j_driver

    def test_recommendation_nodes_created(self):
        """Should create Recommendation nodes."""
        with self.driver.session() as session:
            infer(session)
            result = session.run("MATCH (r:Recommendation) RETURN count(r) AS n")
            assert result.single()["n"] == len(_RECOMMENDATIONS)

    def test_recommendation_nodes_have_properties(self):
        """All Recommendation nodes should have key, category, text, priority."""
        with self.driver.session() as session:
            infer(session)
            result = session.run(
                "MATCH (r:Recommendation) WHERE r.text IS NULL OR r.priority IS NULL RETURN count(r) AS n"
            )
            assert result.single()["n"] == 0

    def test_recommendation_import_is_idempotent(self):
        """Running twice should not duplicate nodes."""
        with self.driver.session() as session:
            infer(session)
            count1 = session.run(
                "MATCH (r:Recommendation) RETURN count(r) AS n"
            ).single()["n"]
            infer(session)
            count2 = session.run(
                "MATCH (r:Recommendation) RETURN count(r) AS n"
            ).single()["n"]
            assert count1 == count2
