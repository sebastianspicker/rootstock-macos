"""
test_threat_groups.py — Tests for ATT&CK group correlation and temporal scoring.

Pure unit tests — no Neo4j required for most tests.
Integration tests for import functions use mock sessions.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure graph/ is on sys.path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

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


# ── ThreatGroup dataclass ────────────────────────────────────────────────

class TestThreatGroupDataclass:
    def test_create_basic(self):
        g = ThreatGroup("G0001", "TestGroup")
        assert g.group_id == "G0001"
        assert g.name == "TestGroup"
        assert g.aliases == ()

    def test_create_with_aliases(self):
        g = ThreatGroup("G0002", "TestGroup2", aliases=("Alias1", "Alias2"))
        assert g.aliases == ("Alias1", "Alias2")

    def test_frozen(self):
        g = ThreatGroup("G0001", "TestGroup")
        with pytest.raises(AttributeError):
            g.name = "Changed"  # type: ignore[misc]

    def test_equality(self):
        g1 = ThreatGroup("G0001", "Test", aliases=("A",))
        g2 = ThreatGroup("G0001", "Test", aliases=("A",))
        assert g1 == g2


# ── Group registry ───────────────────────────────────────────────────────

class TestGroupRegistry:
    def test_registry_has_expected_groups(self):
        expected_ids = {"G0096", "G0032", "G0050", "G0046", "G0010",
                        "G0016", "G0007", "G0094", "G9001", "G9002"}
        assert set(_GROUP_REGISTRY.keys()) == expected_ids

    def test_apt41_details(self):
        apt41 = _GROUP_REGISTRY["G0096"]
        assert apt41.name == "APT41"
        assert "Winnti" in apt41.aliases
        assert "Barium" in apt41.aliases

    def test_operation_triangulation(self):
        ot = _GROUP_REGISTRY["G9001"]
        assert ot.name == "Operation Triangulation"

    def test_nso_group(self):
        nso = _GROUP_REGISTRY["G9002"]
        assert "Pegasus" in nso.aliases

    def test_all_groups_have_valid_ids(self):
        for gid, group in _GROUP_REGISTRY.items():
            assert gid == group.group_id
            assert gid.startswith("G")
            assert len(group.name) > 0


# ── Group-technique mapping ──────────────────────────────────────────────

class TestGroupTechniqueMap:
    def test_all_groups_have_technique_mapping(self):
        """Every group in the registry should have a technique mapping."""
        for gid in _GROUP_REGISTRY:
            assert gid in _GROUP_TECHNIQUE_MAP, f"Group {gid} missing from technique map"

    def test_all_mapped_techniques_exist_in_registry(self):
        """Every technique ID in the map should be defined in the ATT&CK registry."""
        all_technique_ids: set[str] = set()
        for ctx in _REGISTRY.values():
            for tech in ctx.techniques:
                all_technique_ids.add(tech.technique_id)

        for gid, tech_ids in _GROUP_TECHNIQUE_MAP.items():
            for tid in tech_ids:
                assert tid in all_technique_ids, (
                    f"Technique {tid} for group {gid} not in ATT&CK registry"
                )

    def test_apt41_techniques(self):
        techs = _GROUP_TECHNIQUE_MAP["G0096"]
        assert "T1574.006" in techs  # Dynamic Linker Hijacking
        assert "T1068" in techs      # Exploitation for Privilege Escalation

    def test_nso_pegasus_techniques(self):
        techs = _GROUP_TECHNIQUE_MAP["G9002"]
        assert "T1068" in techs  # Kernel exploitation
        assert "T1200" in techs  # Hardware Additions


# ── Temporal scoring ─────────────────────────────────────────────────────

class TestTemporalScore:
    def test_perfect_score(self):
        """High CVSS, high EPSS, fresh CVE should score near 1.0."""
        score = temporal_score(cvss=10.0, epss=1.0, years_since_disclosure=0.0)
        assert score == pytest.approx(1.0)

    def test_zero_score(self):
        """Zero CVSS, no EPSS, very old CVE should score near 0.0."""
        score = temporal_score(cvss=0.0, epss=0.0, years_since_disclosure=10.0)
        assert score == pytest.approx(0.0)

    def test_none_epss_treated_as_zero(self):
        score = temporal_score(cvss=5.0, epss=None, years_since_disclosure=1.0)
        expected_cvss = (5.0 / 10.0) * 0.4  # 0.2
        expected_age = max(0, 1 - 1.0 / 5.0) * 0.2  # 0.16
        assert score == pytest.approx(expected_cvss + expected_age)

    def test_age_decay_caps_at_zero(self):
        """CVEs older than 5 years should have 0 age component."""
        score_old = temporal_score(cvss=5.0, epss=0.5, years_since_disclosure=10.0)
        score_5y = temporal_score(cvss=5.0, epss=0.5, years_since_disclosure=5.0)
        assert score_old == score_5y  # Both have age_decay = 0

    def test_mid_range_score(self):
        score = temporal_score(cvss=7.0, epss=0.5, years_since_disclosure=2.0)
        cvss_part = (7.0 / 10.0) * 0.4   # 0.28
        epss_part = 0.5 * 0.4             # 0.20
        age_part = (1 - 2.0 / 5.0) * 0.2  # 0.12
        assert score == pytest.approx(cvss_part + epss_part + age_part)

    def test_score_clamped_to_unit_range(self):
        """Score should always be in [0.0, 1.0]."""
        score = temporal_score(cvss=10.0, epss=1.0, years_since_disclosure=0.0)
        assert 0.0 <= score <= 1.0
        score2 = temporal_score(cvss=0.0, epss=0.0, years_since_disclosure=100.0)
        assert 0.0 <= score2 <= 1.0


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
        assert count == len(_GROUP_REGISTRY)
        # Batched: single UNWIND call
        session.run.assert_called_once()
        batch = session.run.call_args[1]["batch"]
        assert len(batch) == len(_GROUP_REGISTRY)

    def test_import_group_technique_edges(self):
        total_edges = sum(len(techs) for techs in _GROUP_TECHNIQUE_MAP.values())
        session = self._mock_session(return_n=total_edges)
        count = import_group_technique_edges(session)
        assert count == total_edges
        # Batched: single UNWIND call
        session.run.assert_called_once()

    def test_import_all_includes_threat_groups(self):
        session = self._mock_session(return_n=0)
        with patch("import_vulnerabilities.enrich_registry") as mock_enrich:
            mock_enrich.return_value = {}
            counts = import_all(session)
        assert "threat_groups" in counts
        assert "uses_technique" in counts
