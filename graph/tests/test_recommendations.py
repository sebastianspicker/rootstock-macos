"""
test_recommendations.py — Tests for graph-native Recommendation nodes.

Tests infer_recommendations.py — Recommendation node creation,
HAS_RECOMMENDATION edges, and MITIGATES edges.
"""

from __future__ import annotations

from unittest import TestCase

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from infer_recommendations import _RECOMMENDATIONS, RecommendationRule, infer

TEST_MARKER = "rootstock-test-recommendations"
TEST_SCAN_ID = "test-recommendations"
OTHER_SCAN_ID = "test-recommendations-other"


# ── Unit tests ───────────────────────────────────────────────────────────────


checks = TestCase()


class TestRecommendationDefinitions:
    def test_recommendations_exist(self):
        checks.assertGreater(len(_RECOMMENDATIONS), 10)

    def test_each_recommendation_has_required_fields(self):
        """Each recommendation should expose named fields with correct types."""
        for rec in _RECOMMENDATIONS:
            checks.assertTrue(isinstance(rec, RecommendationRule))
            checks.assertTrue(isinstance(rec.key, str) and len(rec.key) > 0)
            checks.assertTrue(isinstance(rec.category, str) and len(rec.category) > 0)
            checks.assertTrue(isinstance(rec.text, str) and len(rec.text) > 0)
            checks.assertIn(rec.priority, ("critical", "high", "medium", "low"))
            checks.assertTrue(isinstance(rec.technique_ids, tuple))
            checks.assertTrue(
                isinstance(rec.condition, str) and len(rec.condition.strip()) > 0
            )

    def test_unique_keys(self):
        """Recommendation keys should be unique."""
        keys = [rec.key for rec in _RECOMMENDATIONS]
        checks.assertEqual(
            len(keys),
            len(set(keys)),
            f"Duplicate keys: {[k for k in keys if keys.count(k) > 1]}",
        )

    def test_technique_ids_are_valid_format(self):
        """Technique IDs should match ATT&CK format (T#### or T####.###)."""
        import re

        for rec in _RECOMMENDATIONS:
            for tid in rec.technique_ids:
                checks.assertTrue(
                    re.match(r"T\d{4}(\.\d{3})?$", tid), f"Invalid technique ID: {tid}"
                )

    def test_file_acl_recommendation_uses_host_scoped_user_path(self):
        recommendation = next(
            rec for rec in _RECOMMENDATIONS if rec.key == "audit_file_acls"
        )
        checks.assertIn("LOCAL_TO", recommendation.condition)
        checks.assertIn("CAN_WRITE", recommendation.condition)

    def test_mdm_recommendation_uses_current_import_relationship(self):
        recommendation = next(
            rec for rec in _RECOMMENDATIONS if rec.key == "review_mdm_pppc"
        )
        checks.assertIn("CONFIGURES", recommendation.condition)
        checks.assertNotIn("MDM_OVERGRANT", recommendation.condition)


class TestInferFunction:
    def test_infer_surfaces_recommendation_edge_failures(self, monkeypatch):
        monkeypatch.setattr(
            "infer_recommendations._RECOMMENDATIONS",
            [RecommendationRule("fixture", "category", "text", "high", (), "true")],
        )
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_session.run.side_effect = [mock_result, RuntimeError("write failed")]

        with pytest.raises(RuntimeError, match="fixture: write failed"):
            infer(mock_session)


# ── Integration tests (require Neo4j) ────────────────────────────────────


class TestRecommendationIntegration:
    @pytest.fixture(autouse=True)
    def setup(self, neo4j_driver):
        self.driver = neo4j_driver
        with self.driver.session() as session:
            self._cleanup(session)
        yield
        with self.driver.session() as session:
            self._cleanup(session)

    def _cleanup(self, session):
        session.run(
            "MATCH (n {test_marker: $marker}) DETACH DELETE n",
            marker=TEST_MARKER,
        )

    def _recommendation_keys_for(self, session, app_key: str) -> list[str]:
        result = session.run(
            """
            MATCH (:Application {app_key: $app_key})
                  -[:HAS_RECOMMENDATION]->(r:Recommendation)
            RETURN collect(r.key) AS keys
            """,
            app_key=app_key,
        )
        record = result.single()
        return sorted(record["keys"] if record else [])

    def _seed_injectable_fda_case(self, session) -> tuple[str, str]:
        positive = "test-rec-injectable-fda-positive"
        negative = "test-rec-injectable-fda-negative"
        session.run(
            """
            MERGE (fda:TCC_Permission {service: 'kTCCServiceSystemPolicyAllFiles'})
            CREATE (positive:Application {
                app_key: $positive,
                bundle_id: 'com.example.rec.injectable-positive',
                name: 'Injectable FDA Positive',
                scan_id: $scan_id,
                injection_methods: ['electron_env_var'],
                is_sandboxed: true,
                test_marker: $marker
            })
            CREATE (negative:Application {
                app_key: $negative,
                bundle_id: 'com.example.rec.injectable-negative',
                name: 'Injectable FDA Negative',
                scan_id: $scan_id,
                injection_methods: [],
                is_sandboxed: true,
                test_marker: $marker
            })
            CREATE (positive)-[:HAS_TCC_GRANT {allowed: true}]->(fda)
            CREATE (negative)-[:HAS_TCC_GRANT {allowed: true}]->(fda)
            """,
            marker=TEST_MARKER,
            scan_id=TEST_SCAN_ID,
            positive=positive,
            negative=negative,
        )
        return positive, negative

    def _seed_mdm_pppc_case(self, session) -> tuple[str, str]:
        positive = "test-rec-mdm-positive"
        negative = "test-rec-mdm-negative"
        session.run(
            """
            MERGE (apple:TCC_Permission {service: 'kTCCServiceAppleEvents'})
            MERGE (profile:MDM_Profile {identifier: 'test-rec-mdm-profile'})
            SET profile.test_marker = $marker
            CREATE (positive:Application {
                app_key: $positive,
                bundle_id: 'com.example.rec.mdm-positive',
                name: 'MDM PPPC Positive',
                scan_id: $scan_id,
                injection_methods: [],
                test_marker: $marker
            })
            CREATE (negative:Application {
                app_key: $negative,
                bundle_id: 'com.example.rec.mdm-negative',
                name: 'MDM PPPC Negative',
                scan_id: $scan_id,
                injection_methods: [],
                test_marker: $marker
            })
            CREATE (positive)-[:HAS_TCC_GRANT {allowed: true}]->(apple)
            CREATE (negative)-[:HAS_TCC_GRANT {allowed: true}]->(apple)
            CREATE (profile)-[:CONFIGURES {
                bundle_id: 'com.example.rec.mdm-positive',
                allowed: true
            }]->(apple)
            """,
            marker=TEST_MARKER,
            scan_id=TEST_SCAN_ID,
            positive=positive,
            negative=negative,
        )
        return positive, negative

    def _seed_file_acl_case(self, session) -> tuple[str, str, str]:
        positive = "test-rec-file-acl-positive"
        negative = "test-rec-file-acl-negative"
        other_scan = "test-rec-file-acl-other-scan"
        self._seed_file_acl_nodes(session, positive, negative, other_scan)
        self._seed_file_acl_relationships(session)
        return positive, negative, other_scan

    def _seed_file_acl_nodes(
        self, session, positive: str, negative: str, other_scan: str
    ) -> None:
        self._seed_file_acl_host_nodes(session)
        self._seed_file_acl_application_nodes(session, positive, negative, other_scan)

    def _seed_file_acl_host_nodes(self, session) -> None:
        session.run(
            """
            CREATE (computer:Computer {
                computer_key: 'test-rec-computer',
                hostname: 'test-rec-host',
                test_marker: $marker
            })
            CREATE (isolated:Computer {
                computer_key: 'test-rec-isolated-computer',
                hostname: 'test-rec-isolated-host',
                test_marker: $marker
            })
            CREATE (user:User {
                name: 'test-rec-user',
                test_marker: $marker
            })
            CREATE (critical:CriticalFile {
                path: '/tmp/rootstock-test-critical-file',
                test_marker: $marker
            })
            """,
            marker=TEST_MARKER,
        )

    def _seed_file_acl_application_nodes(
        self, session, positive: str, negative: str, other_scan: str
    ) -> None:
        session.run(
            """
            CREATE (positive:Application {
                app_key: $positive,
                bundle_id: 'com.example.rec.file-acl-positive',
                name: 'File ACL Positive',
                scan_id: $scan_id,
                injection_methods: [],
                test_marker: $marker
            })
            CREATE (negative:Application {
                app_key: $negative,
                bundle_id: 'com.example.rec.file-acl-negative',
                name: 'File ACL Negative',
                scan_id: $scan_id,
                injection_methods: [],
                test_marker: $marker
            })
            CREATE (other:Application {
                app_key: $other_scan,
                bundle_id: 'com.example.rec.file-acl-other-scan',
                name: 'File ACL Other Scan',
                scan_id: $other_scan_id,
                injection_methods: [],
                test_marker: $marker
            })
            """,
            marker=TEST_MARKER,
            scan_id=TEST_SCAN_ID,
            other_scan_id=OTHER_SCAN_ID,
            positive=positive,
            negative=negative,
            other_scan=other_scan,
        )

    def _seed_file_acl_relationships(self, session) -> None:
        session.run(
            """
            MATCH (computer:Computer {computer_key: 'test-rec-computer'})
            MATCH (isolated:Computer {computer_key: 'test-rec-isolated-computer'})
            MATCH (user:User {name: 'test-rec-user'})
            MATCH (critical:CriticalFile {path: '/tmp/rootstock-test-critical-file'})
            MATCH (positive:Application {app_key: 'test-rec-file-acl-positive'})
            MATCH (negative:Application {app_key: 'test-rec-file-acl-negative'})
            MATCH (other:Application {app_key: 'test-rec-file-acl-other-scan'})
            CREATE (positive)-[:INSTALLED_ON]->(computer)
            CREATE (negative)-[:INSTALLED_ON]->(isolated)
            CREATE (other)-[:INSTALLED_ON]->(isolated)
            CREATE (user)-[:LOCAL_TO]->(computer)
            CREATE (user)-[:CAN_WRITE]->(critical)
            """
        )

    def test_recommendation_nodes_created(self):
        """Should create Recommendation nodes."""
        with self.driver.session() as session:
            infer(session)
            result = session.run("MATCH (r:Recommendation) RETURN count(r) AS n")
            checks.assertEqual(result.single()["n"], len(_RECOMMENDATIONS))

    def test_recommendation_nodes_have_properties(self):
        """All Recommendation nodes should have key, category, text, priority."""
        with self.driver.session() as session:
            infer(session)
            result = session.run(
                "MATCH (r:Recommendation) WHERE r.text IS NULL OR r.priority IS NULL RETURN count(r) AS n"
            )
            checks.assertEqual(result.single()["n"], 0)

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
            checks.assertEqual(count1, count2)

    def test_injectable_fda_recommendations_match_only_injectable_fda_apps(self):
        with self.driver.session() as session:
            positive, negative = self._seed_injectable_fda_case(session)

            infer(session)

            positive_keys = self._recommendation_keys_for(session, positive)
            negative_keys = self._recommendation_keys_for(session, negative)
            checks.assertIn("harden_runtime", positive_keys)
            checks.assertIn("audit_fda_grants", positive_keys)
            checks.assertNotIn("harden_runtime", negative_keys)
            checks.assertNotIn("audit_fda_grants", negative_keys)

    def test_mdm_pppc_recommendation_requires_matching_allowed_profile(self):
        with self.driver.session() as session:
            positive, negative = self._seed_mdm_pppc_case(session)

            infer(session)

            checks.assertIn(
                "review_mdm_pppc", self._recommendation_keys_for(session, positive)
            )
            checks.assertNotIn(
                "review_mdm_pppc", self._recommendation_keys_for(session, negative)
            )

    def test_file_acl_recommendation_requires_local_writable_critical_file(self):
        with self.driver.session() as session:
            positive, negative, other_scan = self._seed_file_acl_case(session)

            infer(session)

            checks.assertIn(
                "audit_file_acls", self._recommendation_keys_for(session, positive)
            )
            checks.assertNotIn(
                "audit_file_acls", self._recommendation_keys_for(session, negative)
            )
            checks.assertNotIn(
                "audit_file_acls", self._recommendation_keys_for(session, other_scan)
            )

    def test_recommendation_edges_are_idempotent_for_matching_apps(self):
        with self.driver.session() as session:
            positive, _, _ = self._seed_file_acl_case(session)

            infer(session)
            infer(session)

            result = session.run(
                """
                MATCH (:Application {app_key: $app_key})
                      -[rel:HAS_RECOMMENDATION]->
                      (:Recommendation {key: 'audit_file_acls'})
                RETURN count(rel) AS n
                """,
                app_key=positive,
            )
            checks.assertEqual(result.single()["n"], 1)
