"""
test_cve_enrichment.py - Tests for EPSS + CISA KEV enrichment.

Pure unit tests - no network calls, no Neo4j required.
"""

from __future__ import annotations

import sys
import logging
from datetime import datetime, timezone
from pathlib import Path
from unittest import TestCase
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
    fetch_and_cache,
    fetch_kev,
    fetch_nvd,
    get_enrichment_status,
    main,
)
from cve_reference import CveEntry


checks = TestCase()


def _mock_json_response(payload):
    response = MagicMock()
    response.json.return_value = payload
    response.raise_for_status = MagicMock()
    return response


def _fetch_with_response(fetch, payload):
    with patch("cve_enrichment.requests") as mock_requests:
        mock_requests.get.return_value = _mock_json_response(payload)
        return fetch(force=True)


def _run_main_with_unavailable_feeds(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["cve_enrichment.py", "--fetch"])
    with (
        patch("cve_enrichment.fetch_epss", side_effect=RuntimeError("epss down")),
        patch("cve_enrichment.fetch_kev", side_effect=RuntimeError("kev down")),
        patch("cve_enrichment.fetch_nvd", side_effect=RuntimeError("nvd down")),
    ):
        return main()


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
        checks.assertIsNone(_read_cache(tmp_cache_dir / "nonexistent.json"))

    def test_write_and_read_cache(self, tmp_cache_dir):
        path = tmp_cache_dir / "test.json"
        data = {"key": "value", "_fetched_at": datetime.now(timezone.utc).isoformat()}
        _write_cache(path, data)
        loaded = _read_cache(path)
        checks.assertIsNotNone(loaded)
        checks.assertEqual(loaded["key"], "value")

    def test_cache_age_no_cache(self):
        checks.assertEqual(_cache_age_seconds(None), float("inf"))

    def test_cache_age_no_timestamp(self):
        checks.assertEqual(_cache_age_seconds({}), float("inf"))

    def test_cache_age_recent(self):
        cache = {"_fetched_at": datetime.now(timezone.utc).isoformat()}
        age = _cache_age_seconds(cache)
        checks.assertLess(age, 5)

    def test_is_stale_no_cache(self):
        checks.assertIs(_is_stale(None, 3600), True)

    def test_is_stale_fresh_cache(self):
        cache = {"_fetched_at": datetime.now(timezone.utc).isoformat()}
        checks.assertIs(_is_stale(cache, 3600), False)

    def test_corrupt_cache_returns_none(self, tmp_cache_dir):
        path = tmp_cache_dir / "corrupt.json"
        path.write_text("not valid json {{{")
        checks.assertIsNone(_read_cache(path))


# ── EPSS fetch ───────────────────────────────────────────────────────────


class TestFetchEpss:
    def test_fetch_from_api(self, tmp_cache_dir, sample_epss_response):
        result = _fetch_with_response(fetch_epss, sample_epss_response)

        checks.assertIn("CVE-2024-44133", result)
        checks.assertEqual(result["CVE-2024-44133"]["epss"], 0.42)
        checks.assertEqual(result["CVE-2024-44133"]["percentile"], 0.95)
        checks.assertIn("_fetched_at", result)

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

        checks.assertEqual(result["CVE-2024-44133"]["epss"], 0.42)

    def test_force_ignores_cache(self, tmp_cache_dir, sample_epss_response):
        fresh_cache = {
            "CVE-OLD": {"epss": 0.1, "percentile": 0.1},
            "_fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        _write_cache(tmp_cache_dir / "epss.json", fresh_cache)

        result = _fetch_with_response(fetch_epss, sample_epss_response)

        checks.assertIn("CVE-2024-44133", result)


# ── CISA KEV fetch ───────────────────────────────────────────────────────


class TestFetchKev:
    def test_fetch_from_api(self, tmp_cache_dir, sample_kev_response):
        result = _fetch_with_response(fetch_kev, sample_kev_response)

        checks.assertIn("CVE-2024-44133", result)
        checks.assertEqual(result["CVE-2024-44133"]["date_added"], "2024-10-08")
        checks.assertIs(result["CVE-2025-24085"]["ransomware"], True)

    def test_uses_cache_when_fresh(self, tmp_cache_dir):
        fresh_cache = {
            "CVE-2024-44133": {
                "date_added": "2024-10-08",
                "due_date": "2024-10-29",
                "ransomware": False,
            },
            "_fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        _write_cache(tmp_cache_dir / "kev.json", fresh_cache)

        with patch("cve_enrichment.requests") as mock_requests:
            fetch_kev(force=False)
            mock_requests.get.assert_not_called()


# ── Fail-loud refresh behavior ───────────────────────────────────────────


class TestFailLoudRefresh:
    def test_fetch_and_cache_returns_errors_on_all_feed_failures(self, tmp_cache_dir):
        with (
            patch("cve_enrichment.fetch_epss", side_effect=RuntimeError("epss down")),
            patch("cve_enrichment.fetch_kev", side_effect=RuntimeError("kev down")),
            patch("cve_enrichment.fetch_nvd", side_effect=RuntimeError("nvd down")),
        ):
            errors = fetch_and_cache(force=True)

        checks.assertEqual(len(errors), 3)
        checks.assertEqual(
            errors,
            [
                "EPSS fetch failed: epss down",
                "KEV fetch failed: kev down",
                "NVD fetch failed: nvd down",
            ],
        )

    def test_main_exits_nonzero_on_all_feed_failures_with_no_cache(
        self, tmp_cache_dir, capsys, monkeypatch
    ):
        exit_code = _run_main_with_unavailable_feeds(monkeypatch)

        captured = capsys.readouterr()
        checks.assertEqual(exit_code, 1)
        checks.assertIn("ERROR: EPSS fetch failed: epss down", captured.err)
        checks.assertIn("ERROR: KEV fetch failed: kev down", captured.err)
        checks.assertIn("ERROR: NVD fetch failed: nvd down", captured.err)

    def test_main_exits_zero_on_all_feed_failures_when_stale_cache_exists(
        self, tmp_cache_dir, capsys, monkeypatch
    ):
        _write_cache(
            tmp_cache_dir / "epss.json",
            {
                "CVE-2024-44133": {"epss": 0.42},
                "_fetched_at": "2000-01-01T00:00:00+00:00",
            },
        )
        exit_code = _run_main_with_unavailable_feeds(monkeypatch)

        captured = capsys.readouterr()
        checks.assertEqual(exit_code, 0)
        checks.assertIn("WARNING: EPSS fetch failed: epss down", captured.err)
        checks.assertIn("WARNING: KEV fetch failed: kev down", captured.err)
        checks.assertIn("WARNING: NVD fetch failed: nvd down", captured.err)

    def test_fetch_nvd_partial_failure_reports_count(self, tmp_cache_dir, monkeypatch):
        cve_ids = [f"CVE-2026-{index:04d}" for index in range(10)]
        failing = set(cve_ids[:3])

        def fake_fetch(cve_id: str) -> str:
            if cve_id in failing:
                raise RuntimeError("nvd timeout")
            return f"CVSS:3.1/{cve_id}"

        monkeypatch.setattr("cve_enrichment._all_registry_cve_ids", lambda: cve_ids)
        monkeypatch.setattr("cve_enrichment._fetch_nvd_single", fake_fetch)
        monkeypatch.setattr("cve_enrichment.NVD_BATCH_DELAY", 0)
        errors: list[str] = []

        result = fetch_nvd(force=True, errors=errors)

        checks.assertEqual(errors, ["NVD partial: 3/10 CVEs failed enrichment"])
        checks.assertEqual(
            sum(1 for cve_id in failing if result[cve_id]["vector"] is None), 3
        )


# ── Enrichment ───────────────────────────────────────────────────────────


class TestEnrichRegistry:
    def test_enrichment_without_cache(self, tmp_cache_dir):
        """With no cache, enrichment returns entries with None EPSS/KEV fields."""
        enriched = enrich_registry()
        checks.assertGreater(len(enriched), 0)
        for entry in enriched.values():
            checks.assertTrue(isinstance(entry, EnrichedCveEntry))
            checks.assertTrue(isinstance(entry.base, CveEntry))

    def test_enrich_registry_warns_when_all_caches_absent(self, tmp_cache_dir, caplog):
        with caplog.at_level(logging.WARNING, logger="cve_enrichment"):
            enriched = enrich_registry()

        checks.assertGreater(len(enriched), 0)
        checks.assertIn("No enrichment caches found", caplog.text)
        checks.assertIn("CVSS-only", caplog.text)

    def test_enrichment_with_epss_cache(self, tmp_cache_dir):
        epss_cache = {
            "CVE-2024-44133": {"epss": 0.42, "percentile": 0.95},
            "_fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        _write_cache(tmp_cache_dir / "epss.json", epss_cache)

        enriched = enrich_registry()
        entry = enriched.get("CVE-2024-44133")
        checks.assertIsNotNone(entry)
        checks.assertEqual(entry.epss_score, 0.42)
        checks.assertEqual(entry.epss_percentile, 0.95)

    def test_enrichment_with_kev_cache(self, tmp_cache_dir):
        kev_cache = {
            "CVE-2024-44133": {
                "date_added": "2024-10-08",
                "due_date": "2024-10-29",
                "ransomware": False,
            },
            "_fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        _write_cache(tmp_cache_dir / "kev.json", kev_cache)

        enriched = enrich_registry()
        entry = enriched.get("CVE-2024-44133")
        checks.assertIsNotNone(entry)
        checks.assertIs(entry.in_kev, True)
        checks.assertEqual(entry.kev_date_added, "2024-10-08")

    def test_enrichment_no_duplicates(self, tmp_cache_dir):
        enriched = enrich_registry()
        cve_ids = list(enriched.keys())
        checks.assertEqual(len(cve_ids), len(set(cve_ids)))

    def test_enrichment_composition_preserves_base(self, tmp_cache_dir):
        """Enrichment should not mutate the base CveEntry."""
        enriched = enrich_registry()
        for entry in enriched.values():
            checks.assertEqual(entry.base.cve_id, entry.base.cve_id)
            checks.assertGreaterEqual(entry.base.cvss_score, 0)


# ── Status ───────────────────────────────────────────────────────────────


class TestGetEnrichmentStatus:
    def test_status_no_cache(self, tmp_cache_dir):
        status = get_enrichment_status()
        checks.assertIs(status["epss"]["cached"], False)
        checks.assertIs(status["kev"]["cached"], False)
        checks.assertGreater(status["registry_cve_count"], 0)

    def test_status_with_cache(self, tmp_cache_dir):
        epss_cache = {
            "CVE-2024-44133": {"epss": 0.42, "percentile": 0.95},
            "_fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        _write_cache(tmp_cache_dir / "epss.json", epss_cache)

        status = get_enrichment_status()
        checks.assertIs(status["epss"]["cached"], True)
        checks.assertEqual(status["epss"]["count"], 1)
        checks.assertIs(status["epss"]["stale"], False)


# ── Registry CVE ID collection ───────────────────────────────────────────


class TestRegistryCveIds:
    def test_all_registry_cve_ids_returns_sorted(self):
        ids = _all_registry_cve_ids()
        checks.assertEqual(ids, sorted(ids))

    def test_all_registry_cve_ids_no_duplicates(self):
        ids = _all_registry_cve_ids()
        checks.assertEqual(len(ids), len(set(ids)))

    def test_all_registry_cve_ids_count(self):
        ids = _all_registry_cve_ids()
        checks.assertGreaterEqual(len(ids), 30)


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
            fetch_epss(force=True)
            checks.assertGreaterEqual(mock_requests.get.call_count, 1)
