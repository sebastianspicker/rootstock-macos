"""
test_threat_groups.py — Tests for ATT&CK group correlation and temporal scoring.

Pure unit tests — no Neo4j required for most tests.
Integration tests for import functions use mock sessions.
"""

from __future__ import annotations

from unittest import TestCase
from unittest.mock import MagicMock, patch

import pytest

from cve_reference import (
    ThreatGroup,
    _GROUP_REGISTRY,
    _GROUP_TECHNIQUE_MAP,
    _REGISTRY,
)
from cve_enrichment import temporal_score
from import_vulnerabilities import (
    import_threat_group_nodes,
    import_group_technique_edges,
    import_all,
)

TEST_GROUP_IDS = ["G9900"]
TEST_TECHNIQUE_IDS = ["T9999.900"]


# ── ThreatGroup dataclass ────────────────────────────────────────────────

checks = TestCase()


class TestThreatGroupDataclass:
    def test_create_basic(self):
        g = ThreatGroup("G0001", "TestGroup")
        checks.assertEqual(g.group_id, "G0001")
        checks.assertEqual(g.name, "TestGroup")
        checks.assertEqual(g.aliases, ())

    def test_create_with_aliases(self):
        g = ThreatGroup("G0002", "TestGroup2", aliases=("Alias1", "Alias2"))
        checks.assertEqual(g.aliases, ("Alias1", "Alias2"))

    def test_frozen(self):
        g = ThreatGroup("G0001", "TestGroup")
        with pytest.raises(AttributeError):
            g.name = "Changed"  # type: ignore[misc]

    def test_equality(self):
        g1 = ThreatGroup("G0001", "Test", aliases=("A",))
        g2 = ThreatGroup("G0001", "Test", aliases=("A",))
        checks.assertEqual(g1, g2)


# ── Group registry ───────────────────────────────────────────────────────


class TestGroupRegistry:
    def test_registry_has_expected_groups(self):
        expected_ids = {
            "G0096",
            "G0032",
            "G0050",
            "G0046",
            "G0010",
            "G0016",
            "G0007",
            "G0094",
            "G9001",
            "G9002",
        }
        checks.assertEqual(set(_GROUP_REGISTRY.keys()), expected_ids)

    def test_apt41_details(self):
        apt41 = _GROUP_REGISTRY["G0096"]
        checks.assertEqual(apt41.name, "APT41")
        checks.assertIn("Winnti", apt41.aliases)
        checks.assertIn("Barium", apt41.aliases)

    def test_operation_triangulation(self):
        ot = _GROUP_REGISTRY["G9001"]
        checks.assertEqual(ot.name, "Operation Triangulation")

    def test_nso_group(self):
        nso = _GROUP_REGISTRY["G9002"]
        checks.assertIn("Pegasus", nso.aliases)

    def test_all_groups_have_valid_ids(self):
        for gid, group in _GROUP_REGISTRY.items():
            checks.assertEqual(gid, group.group_id)
            checks.assertTrue(gid.startswith("G"))
            checks.assertGreater(len(group.name), 0)


# ── Group-technique mapping ──────────────────────────────────────────────


class TestGroupTechniqueMap:
    def test_all_groups_have_technique_mapping(self):
        """Every group in the registry should have a technique mapping."""
        for gid in _GROUP_REGISTRY:
            checks.assertIn(
                gid, _GROUP_TECHNIQUE_MAP, f"Group {gid} missing from technique map"
            )

    def test_all_mapped_techniques_exist_in_registry(self):
        """Every technique ID in the map should be defined in the ATT&CK registry."""
        all_technique_ids: set[str] = set()
        for ctx in _REGISTRY.values():
            for tech in ctx.techniques:
                all_technique_ids.add(tech.technique_id)

        for gid, tech_ids in _GROUP_TECHNIQUE_MAP.items():
            for tid in tech_ids:
                checks.assertIn(
                    tid,
                    all_technique_ids,
                    f"Technique {tid} for group {gid} not in ATT&CK registry",
                )

    def test_apt41_techniques(self):
        techs = _GROUP_TECHNIQUE_MAP["G0096"]
        checks.assertIn("T1574.006", techs)
        checks.assertIn("T1068", techs)

    def test_nso_pegasus_techniques(self):
        techs = _GROUP_TECHNIQUE_MAP["G9002"]
        checks.assertIn("T1068", techs)
        checks.assertIn("T1200", techs)


# ── Temporal scoring ─────────────────────────────────────────────────────


class TestTemporalScore:
    def test_perfect_score(self):
        """High CVSS, high EPSS, fresh CVE should score near 1.0."""
        score = temporal_score(cvss=10.0, epss=1.0, years_since_disclosure=0.0)
        checks.assertEqual(score, pytest.approx(1.0))

    def test_zero_score(self):
        """Zero CVSS, no EPSS, very old CVE should score near 0.0."""
        score = temporal_score(cvss=0.0, epss=0.0, years_since_disclosure=10.0)
        checks.assertEqual(score, pytest.approx(0.0))

    def test_none_epss_treated_as_zero(self):
        score = temporal_score(cvss=5.0, epss=None, years_since_disclosure=1.0)
        expected_cvss = (5.0 / 10.0) * 0.4  # 0.2
        expected_age = max(0, 1 - 1.0 / 5.0) * 0.2  # 0.16
        checks.assertEqual(score, pytest.approx(expected_cvss + expected_age))

    def test_age_decay_caps_at_zero(self):
        """CVEs older than 5 years should have 0 age component."""
        score_old = temporal_score(cvss=5.0, epss=0.5, years_since_disclosure=10.0)
        score_5y = temporal_score(cvss=5.0, epss=0.5, years_since_disclosure=5.0)
        checks.assertEqual(score_old, score_5y)

    def test_mid_range_score(self):
        score = temporal_score(cvss=7.0, epss=0.5, years_since_disclosure=2.0)
        cvss_part = (7.0 / 10.0) * 0.4  # 0.28
        epss_part = 0.5 * 0.4  # 0.20
        age_part = (1 - 2.0 / 5.0) * 0.2  # 0.12
        checks.assertEqual(score, pytest.approx(cvss_part + epss_part + age_part))

    def test_score_clamped_to_unit_range(self):
        """Score should always be in [0.0, 1.0]."""
        score = temporal_score(cvss=10.0, epss=1.0, years_since_disclosure=0.0)
        checks.assertTrue(0.0 <= score <= 1.0)
        score2 = temporal_score(cvss=0.0, epss=0.0, years_since_disclosure=100.0)
        checks.assertTrue(0.0 <= score2 <= 1.0)


# ── Import functions (mock session) ──────────────────────────────────────


class TestImportThreatGroups:
    def _mock_session(self, return_n=None):
        session = MagicMock()
        result = MagicMock()
        if return_n is not None:
            result.single.return_value = {"n": return_n}
        else:
            result.single.return_value = {"n": 1}
        session.run.return_value = result
        return session

    def test_import_threat_group_nodes(self):
        session = self._mock_session(return_n=len(_GROUP_REGISTRY))
        count = import_threat_group_nodes(session)
        checks.assertEqual(count, len(_GROUP_REGISTRY))
        # Batched: single UNWIND call
        session.run.assert_called_once()
        batch = session.run.call_args[1]["batch"]
        checks.assertEqual(len(batch), len(_GROUP_REGISTRY))

    def test_import_group_technique_edges(self):
        total_edges = sum(len(techs) for techs in _GROUP_TECHNIQUE_MAP.values())
        session = self._mock_session(return_n=total_edges)
        count = import_group_technique_edges(session)
        checks.assertEqual(count, total_edges)
        # Batched: single UNWIND call
        session.run.assert_called_once()

    def test_import_all_includes_threat_groups(self):
        session = self._mock_session(return_n=0)
        with patch("import_vulnerabilities.enrich_registry") as mock_enrich:
            mock_enrich.return_value = {}
            counts = import_all(session)
        checks.assertIn("threat_groups", counts)
        checks.assertIn("uses_technique", counts)


# ── Integration tests (require Neo4j) ────────────────────────────────────


class TestThreatGroupIntegration:
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
            """
            MATCH (n)
            WHERE n.group_id IN $group_ids OR n.technique_id IN $technique_ids
            DETACH DELETE n
            """,
            group_ids=TEST_GROUP_IDS,
            technique_ids=TEST_TECHNIQUE_IDS,
        )

    def test_threat_group_edges_attach_only_to_existing_techniques(self):
        group = ThreatGroup("G9900", "Fixture Group", aliases=("FixtureAlias",))

        with self.driver.session() as session:
            session.run(
                """
                CREATE (:AttackTechnique {
                    technique_id: 'T9999.900',
                    name: 'Fixture Technique',
                    tactic: 'Execution'
                })
                """
            )

            with (
                patch("import_vulnerabilities._GROUP_REGISTRY", {"G9900": group}),
                patch(
                    "import_vulnerabilities._GROUP_TECHNIQUE_MAP",
                    {"G9900": ["T9999.900", "T9999.MISSING"]},
                ),
            ):
                import_threat_group_nodes(session)
                import_group_technique_edges(session)

            result = session.run(
                """
                MATCH (g:ThreatGroup {group_id: 'G9900'})
                OPTIONAL MATCH (g)-[:USES_TECHNIQUE]->(t:AttackTechnique)
                RETURN g.name AS name,
                       g.aliases AS aliases,
                       collect(t.technique_id) AS technique_ids
                """
            )
            record = result.single()
            checks.assertEqual(record["name"], "Fixture Group")
            checks.assertEqual(record["aliases"], ["FixtureAlias"])
            checks.assertEqual(record["technique_ids"], ["T9999.900"])
