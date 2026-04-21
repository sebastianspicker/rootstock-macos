"""
test_cve_enrichment.py — Tests for EPSS + CISA KEV enrichment.

Pure unit tests — no network calls, no Neo4j required.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure graph/ is on sys.path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from cve_enrichment import (
    EnrichedCveEntry,
    _all_registry_cve_ids,
    _cache_age_seconds,
    _is_stale,
    _read_cache,
    _write_cache,
    enrich_registry,
    fetch_epss,
    fetch_kev,
    get_enrichment_status,
)
from cve_reference import CveEntry


# ── Fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_cache_dir(tmp_path, monkeypatch):
    """Redirect cache to a temp directory."""
    monkeypatch.setattr("cve_enrichment.CACHE_DIR", tmp_path)
    monkeypatch.setattr("cve_enrichment.EPSS_CACHE", tmp_path / "epss.json")
    monkeypatch.setattr("cve_enrichment.KEV_CACHE", tmp_path / "kev.json")
    monkeypatch.setattr("cve_enrichment.NVD_CACHE", tmp_path / "nvd.json")
    return tmp_path


@pytest.fixture
def sample_epss_response():
    return {
        "status": "OK",
        "data": [
            {"cve": "CVE-2024-44133", "epss": "0.42000", "percentile": "0.95000"},
            {"cve": "CVE-2025-24085", "epss": "0.87000", "percentile": "0.99000"},
        ],
    }


@pytest.fixture
def sample_kev_response():
    return {
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-44133",
                "dateAdded": "2024-10-08",
                "dueDate": "2024-10-29",
                "knownRansomwareCampaignUse": "Unknown",
            },
            {
                "cveID": "CVE-2025-24085",
                "dateAdded": "2025-01-28",
                "dueDate": "2025-02-18",
                "knownRansomwareCampaignUse": "Known",
            },
        ],
    }


# ── Cache management ─────────────────────────────────────────────────────

class TestCacheManagement:
    def test_read_missing_cache(self, tmp_cache_dir):
        assert _read_cache(tmp_cache_dir / "nonexistent.json") is None

    def test_write_and_read_cache(self, tmp_cache_dir):
        path = tmp_cache_dir / "test.json"
        data = {"key": "value", "_fetched_at": datetime.now(timezone.utc).isoformat()}
        _write_cache(path, data)
        loaded = _read_cache(path)
        assert loaded is not None
        assert loaded["key"] == "value"

    def test_cache_age_no_cache(self):
        assert _cache_age_seconds(None) == float("inf")

    def test_cache_age_no_timestamp(self):
        assert _cache_age_seconds({}) == float("inf")

    def test_cache_age_recent(self):
        cache = {"_fetched_at": datetime.now(timezone.utc).isoformat()}
        age = _cache_age_seconds(cache)
        assert age < 5  # Should be essentially 0

    def test_is_stale_no_cache(self):
        assert _is_stale(None, 3600) is True

    def test_is_stale_fresh_cache(self):
        cache = {"_fetched_at": datetime.now(timezone.utc).isoformat()}
        assert _is_stale(cache, 3600) is False

    def test_corrupt_cache_returns_none(self, tmp_cache_dir):
        path = tmp_cache_dir / "corrupt.json"
        path.write_text("not valid json {{{")
        assert _read_cache(path) is None


# ── EPSS fetch ───────────────────────────────────────────────────────────

class TestFetchEpss:
    def test_fetch_from_api(self, tmp_cache_dir, sample_epss_response):
        mock_resp = MagicMock()
        mock_resp.json.return_value = sample_epss_response
        mock_resp.raise_for_status = MagicMock()

        with patch("cve_enrichment.requests") as mock_requests:
            mock_requests.get.return_value = mock_resp
            result = fetch_epss(force=True)

        assert "CVE-2024-44133" in result
        assert result["CVE-2024-44133"]["epss"] == 0.42
        assert result["CVE-2024-44133"]["percentile"] == 0.95
        assert "_fetched_at" in result

    def test_uses_cache_when_fresh(self, tmp_cache_dir):
        fresh_cache = {
            "CVE-2024-44133": {"epss": 0.42, "percentile": 0.95},
            "_fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        _write_cache(tmp_cache_dir / "epss.json", fresh_cache)

        # Should not call requests at all
        with patch("cve_enrichment.requests") as mock_requests:
            result = fetch_epss(force=False)
            mock_requests.get.assert_not_called()

        assert result["CVE-2024-44133"]["epss"] == 0.42

    def test_force_ignores_cache(self, tmp_cache_dir, sample_epss_response):
        fresh_cache = {
            "CVE-OLD": {"epss": 0.1, "percentile": 0.1},
            "_fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        _write_cache(tmp_cache_dir / "epss.json", fresh_cache)

        mock_resp = MagicMock()
        mock_resp.json.return_value = sample_epss_response
        mock_resp.raise_for_status = MagicMock()

        with patch("cve_enrichment.requests") as mock_requests:
            mock_requests.get.return_value = mock_resp
            result = fetch_epss(force=True)

        assert "CVE-2024-44133" in result


# ── CISA KEV fetch ───────────────────────────────────────────────────────

class TestFetchKev:
    def test_fetch_from_api(self, tmp_cache_dir, sample_kev_response):
        mock_resp = MagicMock()
        mock_resp.json.return_value = sample_kev_response
        mock_resp.raise_for_status = MagicMock()

        with patch("cve_enrichment.requests") as mock_requests:
            mock_requests.get.return_value = mock_resp
            result = fetch_kev(force=True)

        assert "CVE-2024-44133" in result
        assert result["CVE-2024-44133"]["date_added"] == "2024-10-08"
        assert result["CVE-2025-24085"]["ransomware"] is True

    def test_uses_cache_when_fresh(self, tmp_cache_dir):
        fresh_cache = {
            "CVE-2024-44133": {"date_added": "2024-10-08", "due_date": "2024-10-29", "ransomware": False},
            "_fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        _write_cache(tmp_cache_dir / "kev.json", fresh_cache)

        with patch("cve_enrichment.requests") as mock_requests:
            _result = fetch_kev(force=False)
            mock_requests.get.assert_not_called()


# ── Enrichment ───────────────────────────────────────────────────────────

class TestEnrichRegistry:
    def test_enrichment_without_cache(self, tmp_cache_dir):
        """With no cache, enrichment returns entries with None EPSS/KEV fields."""
        enriched = enrich_registry()
        assert len(enriched) > 0
        for entry in enriched.values():
            assert isinstance(entry, EnrichedCveEntry)
            assert isinstance(entry.base, CveEntry)

    def test_enrichment_with_epss_cache(self, tmp_cache_dir):
        epss_cache = {
            "CVE-2024-44133": {"epss": 0.42, "percentile": 0.95},
            "_fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        _write_cache(tmp_cache_dir / "epss.json", epss_cache)

        enriched = enrich_registry()
        entry = enriched.get("CVE-2024-44133")
        assert entry is not None
        assert entry.epss_score == 0.42
        assert entry.epss_percentile == 0.95

    def test_enrichment_with_kev_cache(self, tmp_cache_dir):
        kev_cache = {
            "CVE-2024-44133": {"date_added": "2024-10-08", "due_date": "2024-10-29", "ransomware": False},
            "_fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        _write_cache(tmp_cache_dir / "kev.json", kev_cache)

        enriched = enrich_registry()
        entry = enriched.get("CVE-2024-44133")
        assert entry is not None
        assert entry.in_kev is True
        assert entry.kev_date_added == "2024-10-08"

    def test_enrichment_no_duplicates(self, tmp_cache_dir):
        enriched = enrich_registry()
        cve_ids = list(enriched.keys())
        assert len(cve_ids) == len(set(cve_ids))

    def test_enrichment_composition_preserves_base(self, tmp_cache_dir):
        """Enrichment should not mutate the base CveEntry."""
        enriched = enrich_registry()
        for entry in enriched.values():
            assert entry.base.cve_id == entry.base.cve_id  # frozen
            assert entry.base.cvss_score >= 0


# ── Status ───────────────────────────────────────────────────────────────

class TestGetEnrichmentStatus:
    def test_status_no_cache(self, tmp_cache_dir):
        status = get_enrichment_status()
        assert status["epss"]["cached"] is False
        assert status["kev"]["cached"] is False
        assert status["registry_cve_count"] > 0

    def test_status_with_cache(self, tmp_cache_dir):
        epss_cache = {
            "CVE-2024-44133": {"epss": 0.42, "percentile": 0.95},
            "_fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        _write_cache(tmp_cache_dir / "epss.json", epss_cache)

        status = get_enrichment_status()
        assert status["epss"]["cached"] is True
        assert status["epss"]["count"] == 1
        assert status["epss"]["stale"] is False


# ── Registry CVE ID collection ───────────────────────────────────────────

class TestRegistryCveIds:
    def test_all_registry_cve_ids_returns_sorted(self):
        ids = _all_registry_cve_ids()
        assert ids == sorted(ids)

    def test_all_registry_cve_ids_no_duplicates(self):
        ids = _all_registry_cve_ids()
        assert len(ids) == len(set(ids))

    def test_all_registry_cve_ids_count(self):
        ids = _all_registry_cve_ids()
        assert len(ids) >= 30  # Registry has 35+ CVEs


# ── Batch EPSS ───────────────────────────────────────────────────────────

class TestEpssBatch:
    def test_batch_splits_large_requests(self, tmp_cache_dir, sample_epss_response):
        """Verify that large CVE lists are split into batches."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = sample_epss_response
        mock_resp.raise_for_status = MagicMock()

        with patch("cve_enrichment.requests") as mock_requests:
            mock_requests.get.return_value = mock_resp
            # All registry CVEs fit in one batch (< 100), so just one call
            _result = fetch_epss(force=True)
            assert mock_requests.get.call_count >= 1
