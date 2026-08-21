#!/usr/bin/env python3
"""
cve_enrichment.py - Live EPSS + CISA KEV enrichment for Rootstock CVE data.

Fetches exploitation probability (EPSS) and Known Exploited Vulnerabilities (KEV)
data from public APIs, caches locally, and enriches the static CVE registry with
live threat intelligence.

Data sources:
  - EPSS: https://api.first.org/data/v1/epss (batch up to 100 CVEs per request)
  - CISA KEV: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Cache: ~/.rootstock/cache/{epss,kev}.json with configurable TTL.
Offline-first: stale cache used if network fails; no cache falls back to static registry.

Usage:
    python3 graph/cve_enrichment.py --fetch          # download + cache
    python3 graph/cve_enrichment.py --status         # show cache freshness
    python3 graph/cve_enrichment.py --lookup CVE-2024-44133
"""

from __future__ import annotations

import json
import logging
import sys
import time
import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cve_reference import CveEntry, _REGISTRY

try:
    import requests
except ImportError:
    requests = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


# ── Constants ──────────────────────────────────────────────────────────────

CACHE_DIR = Path.home() / ".rootstock" / "cache"
EPSS_CACHE = CACHE_DIR / "epss.json"
KEV_CACHE = CACHE_DIR / "kev.json"

EPSS_TTL_SECONDS = 24 * 3600  # 24 hours
KEV_TTL_SECONDS = 24 * 3600  # 24 hours (aligned with EPSS)

EPSS_API_URL = "https://api.first.org/data/v1/epss"
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CACHE = CACHE_DIR / "nvd.json"
NVD_TTL_SECONDS = 7 * 24 * 3600  # 7 days (NVD data changes infrequently)

EPSS_BATCH_SIZE = 100
NVD_BATCH_DELAY = 6  # NVD rate limit: ~5 requests per 30s without API key
REQUEST_TIMEOUT = 30


# ── Enriched data model ───────────────────────────────────────────────────


@dataclass(frozen=True)
class EnrichedCveEntry:
    """A CveEntry enriched with live EPSS, CISA KEV, and NVD CVSS data."""

    base: CveEntry
    epss_score: float | None = None
    epss_percentile: float | None = None
    in_kev: bool = False
    kev_date_added: str | None = None
    kev_due_date: str | None = None
    kev_ransomware: bool = False
    cvss_vector: str | None = None


# ── Cache management ─────────────────────────────────────────────────────


def _ensure_cache_dir() -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _read_cache(path: Path) -> dict | None:
    """Read a cache file, returning None if missing or corrupt."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _write_cache(path: Path, data: dict) -> None:
    _ensure_cache_dir()
    path.write_text(json.dumps(data, indent=2) + "\n")


def _cache_age_seconds(cache: dict | None) -> float:
    """Return age of cache in seconds, or infinity if missing."""
    if cache is None:
        return float("inf")
    fetched = cache.get("_fetched_at")
    if not fetched:
        return float("inf")
    try:
        then = datetime.fromisoformat(fetched)
        now = datetime.now(timezone.utc)
        return (now - then).total_seconds()
    except (ValueError, TypeError):
        return float("inf")


def _is_stale(cache: dict | None, ttl: float) -> bool:
    return _cache_age_seconds(cache) > ttl


def _cache_entry_count(cache: dict) -> int:
    return sum(1 for key in cache if not key.startswith("_"))


# ── EPSS fetch ───────────────────────────────────────────────────────────


def _all_registry_cve_ids() -> list[str]:
    """Collect all unique CVE IDs from the static registry."""
    seen: set[str] = set()
    result: list[str] = []
    for ctx in _REGISTRY.values():
        for cve in ctx.cves:
            if cve.cve_id not in seen:
                seen.add(cve.cve_id)
                result.append(cve.cve_id)
    return sorted(result)


def _fetch_epss_batch(cve_ids: list[str]) -> dict[str, dict]:
    """Fetch EPSS scores for a batch of CVE IDs (max 100)."""
    if requests is None:
        raise RuntimeError("requests package not installed")

    resp = requests.get(
        EPSS_API_URL,
        params={"cve": ",".join(cve_ids)},
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    data = resp.json()

    result: dict[str, dict] = {}
    for entry in data.get("data", []):
        cve_id = entry.get("cve")
        if cve_id:
            result[cve_id] = {
                "epss": float(entry.get("epss", 0)),
                "percentile": float(entry.get("percentile", 0)),
            }
    return result


def fetch_epss(force: bool = False) -> dict:
    """Fetch EPSS data for all registry CVEs. Returns the cache dict."""
    cache = _read_cache(EPSS_CACHE)

    if not force and cache is not None and not _is_stale(cache, EPSS_TTL_SECONDS):
        return cache

    cve_ids = _all_registry_cve_ids()
    if not cve_ids:
        return cache or {}

    all_epss: dict[str, dict] = {}
    for i in range(0, len(cve_ids), EPSS_BATCH_SIZE):
        batch = cve_ids[i : i + EPSS_BATCH_SIZE]
        batch_result = _fetch_epss_batch(batch)
        all_epss.update(batch_result)

    result = {
        **all_epss,
        "_fetched_at": datetime.now(timezone.utc).isoformat(),
    }
    _write_cache(EPSS_CACHE, result)
    return result


# ── CISA KEV fetch ───────────────────────────────────────────────────────


def fetch_kev(force: bool = False) -> dict:
    """Fetch CISA KEV catalog. Returns the cache dict."""
    if requests is None:
        raise RuntimeError("requests package not installed")

    cache = _read_cache(KEV_CACHE)

    if not force and cache is not None and not _is_stale(cache, KEV_TTL_SECONDS):
        return cache

    resp = requests.get(KEV_FEED_URL, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    raw = resp.json()

    result: dict[str, dict] = {}
    for vuln in raw.get("vulnerabilities", []):
        cve_id = vuln.get("cveID")
        if cve_id:
            result[cve_id] = {
                "date_added": vuln.get("dateAdded"),
                "due_date": vuln.get("dueDate"),
                "ransomware": vuln.get("knownRansomwareCampaignUse", "Unknown")
                == "Known",
            }

    result["_fetched_at"] = datetime.now(timezone.utc).isoformat()  # type: ignore[assignment]
    _write_cache(KEV_CACHE, result)
    return result


# ── NVD CVSS vector fetch ───────────────────────────────────────────────


def _select_nvd_metric_vector(metrics: dict) -> str | None:
    """Return the first available CVSS 3.1 or 3.0 metric vector."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            vector = cvss_data.get("vectorString")
            if vector:
                return vector
    return None


def _fetch_nvd_single(cve_id: str) -> str | None:
    """Fetch CVSS vector string for a single CVE from NVD 2.0 API."""
    if requests is None:
        raise RuntimeError("requests package not installed")

    resp = requests.get(
        NVD_API_URL,
        params={"cveId": cve_id},
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    data = resp.json()

    for vuln in data.get("vulnerabilities", []):
        cve_data = vuln.get("cve", {})
        metrics = cve_data.get("metrics", {})

        vector = _select_nvd_metric_vector(metrics)
        if vector:
            return vector

    return None


def fetch_nvd(force: bool = False, errors: list[str] | None = None) -> dict:
    """Fetch NVD CVSS vector strings for all registry CVEs. Returns the cache dict."""
    cache = _read_cache(NVD_CACHE)

    if not force and cache is not None and not _is_stale(cache, NVD_TTL_SECONDS):
        return cache

    cve_ids = _all_registry_cve_ids()
    if not cve_ids:
        return cache or {}

    all_nvd = _cached_nvd_entries(cache)
    fail_count = _fetch_missing_nvd_vectors(cve_ids, all_nvd, force)
    _record_nvd_failures(fail_count, len(cve_ids), errors)

    result = {
        **all_nvd,
        "_fetched_at": datetime.now(timezone.utc).isoformat(),
    }
    _write_cache(NVD_CACHE, result)
    return result


def _cached_nvd_entries(cache: dict | None) -> dict[str, dict]:
    """Keep existing per-CVE cache entries while dropping metadata keys."""
    if cache is None:
        return {}
    return {key: value for key, value in cache.items() if not key.startswith("_")}


def _fetch_missing_nvd_vectors(
    cve_ids: list[str],
    all_nvd: dict[str, dict],
    force: bool,
) -> int:
    fail_count = 0
    for cve_id in cve_ids:
        if not force and cve_id in all_nvd:
            continue
        try:
            all_nvd[cve_id] = {"vector": _fetch_nvd_single(cve_id)}
            # Rate-limit to stay within NVD's public API limits.
            time.sleep(NVD_BATCH_DELAY)
        except Exception:
            fail_count += 1
            all_nvd[cve_id] = {"vector": None}
    return fail_count


def _record_nvd_failures(
    fail_count: int,
    total_count: int,
    errors: list[str] | None,
) -> None:
    if fail_count and errors is not None:
        errors.append(f"NVD partial: {fail_count}/{total_count} CVEs failed enrichment")


# ── Combined fetch ───────────────────────────────────────────────────────


def _has_any_enrichment_cache() -> bool:
    return any(_read_cache(path) for path in (EPSS_CACHE, KEV_CACHE, NVD_CACHE))


def fetch_and_cache(force: bool = False) -> list[str]:
    """Fetch EPSS, KEV, and NVD data. CLI entry point."""
    errors: list[str] = []

    _fetch_cache_source("EPSS", fetch_epss, "CVEs", force, errors)
    _fetch_cache_source("KEV", fetch_kev, "entries", force, errors)
    _fetch_cache_source(
        "NVD",
        lambda force: fetch_nvd(force=force, errors=errors),
        "CVEs",
        force,
        errors,
    )

    if errors and _has_any_enrichment_cache():
        print("  Using stale cache as fallback")

    return errors


def _fetch_cache_source(
    name: str,
    fetcher,
    count_label: str,
    force: bool,
    errors: list[str],
) -> None:
    display = f"{name}:".ljust(6)
    try:
        cache = fetcher(force=force)
        print(f"  {display}{_cache_entry_count(cache)} {count_label} cached")
    except Exception as e:
        errors.append(f"{name} fetch failed: {e}")
        print(f"  {display}fetch failed ({e})")


# ── Enrichment ───────────────────────────────────────────────────────────


def enrich_registry() -> dict[str, EnrichedCveEntry]:
    """Enrich all registry CVEs with cached EPSS/KEV/NVD data.

    Returns a dict keyed by CVE ID. Works fully offline using cached data.
    Falls back gracefully if no cache exists.
    """
    epss_cache = _read_cache(EPSS_CACHE) or {}
    kev_cache = _read_cache(KEV_CACHE) or {}
    nvd_cache = _read_cache(NVD_CACHE) or {}

    result = {
        cve.cve_id: _enriched_cve_entry(cve, epss_cache, kev_cache, nvd_cache)
        for cve in _unique_registry_cves()
    }
    _warn_if_no_enrichment_cache(epss_cache, kev_cache, nvd_cache)
    return result


def _unique_registry_cves() -> list[CveEntry]:
    result: list[CveEntry] = []
    seen: set[str] = set()
    for ctx in _REGISTRY.values():
        for cve in ctx.cves:
            if cve.cve_id in seen:
                continue
            seen.add(cve.cve_id)
            result.append(cve)
    return result


def _enriched_cve_entry(
    cve: CveEntry,
    epss_cache: dict,
    kev_cache: dict,
    nvd_cache: dict,
) -> EnrichedCveEntry:
    epss_data = epss_cache.get(cve.cve_id)
    kev_data = kev_cache.get(cve.cve_id)
    nvd_data = nvd_cache.get(cve.cve_id)
    return EnrichedCveEntry(
        base=cve,
        epss_score=epss_data["epss"] if epss_data else None,
        epss_percentile=epss_data["percentile"] if epss_data else None,
        in_kev=kev_data is not None,
        kev_date_added=kev_data["date_added"] if kev_data else None,
        kev_due_date=kev_data["due_date"] if kev_data else None,
        kev_ransomware=kev_data.get("ransomware", False) if kev_data else False,
        cvss_vector=nvd_data.get("vector") if nvd_data else None,
    )


def _warn_if_no_enrichment_cache(
    epss_cache: dict,
    kev_cache: dict,
    nvd_cache: dict,
) -> None:
    if epss_cache or kev_cache or nvd_cache:
        return
    logger.warning(
        "No enrichment caches found; scoring uses CVSS-only. "
        "Run --refresh-cve to populate."
    )


# ── Temporal scoring ─────────────────────────────────────────────────────


def temporal_score(
    cvss: float, epss: float | None, years_since_disclosure: float
) -> float:
    """Compute a temporal priority score combining CVSS, EPSS, and age decay.

    Score = (CVSS/10 * 0.4) + (EPSS * 0.4) + (age_decay * 0.2)
    where age_decay = max(0, 1 - years_since_disclosure / 5)

    Returns 0.0-1.0 (higher = more urgent).
    """
    cvss_component = (cvss / 10.0) * 0.4
    epss_component = (epss if epss is not None else 0.0) * 0.4
    age_decay = max(0.0, 1.0 - years_since_disclosure / 5.0)
    age_component = age_decay * 0.2
    return min(1.0, max(0.0, cvss_component + epss_component + age_component))


# ── Status ───────────────────────────────────────────────────────────────


def get_enrichment_status() -> dict:
    """Return cache freshness and stats."""
    epss_cache = _read_cache(EPSS_CACHE)
    kev_cache = _read_cache(KEV_CACHE)
    nvd_cache = _read_cache(NVD_CACHE)

    def _status(cache: dict | None, ttl: float) -> dict:
        if cache is None:
            return {"cached": False, "age_hours": None, "stale": True, "count": 0}
        age = _cache_age_seconds(cache)
        count = sum(1 for k in cache if not k.startswith("_"))
        return {
            "cached": True,
            "fetched_at": cache.get("_fetched_at"),
            "age_hours": round(age / 3600, 1),
            "stale": age > ttl,
            "count": count,
        }

    return {
        "epss": _status(epss_cache, EPSS_TTL_SECONDS),
        "kev": _status(kev_cache, KEV_TTL_SECONDS),
        "nvd": _status(nvd_cache, NVD_TTL_SECONDS),
        "registry_cve_count": len(_all_registry_cve_ids()),
    }


# ── CLI ──────────────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="EPSS + CISA KEV enrichment for Rootstock CVEs"
    )
    parser.add_argument(
        "--fetch", action="store_true", help="Download and cache EPSS + KEV data"
    )
    parser.add_argument("--status", action="store_true", help="Show cache freshness")
    parser.add_argument(
        "--lookup", metavar="CVE_ID", help="Look up enrichment for a specific CVE"
    )
    parser.add_argument(
        "--force", action="store_true", help="Force refresh (ignore TTL)"
    )
    return parser


def _run_fetch(force: bool) -> int:
    print("Fetching CVE enrichment data...")
    errors = fetch_and_cache(force=force)
    if errors and not _has_any_enrichment_cache():
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    for error in errors:
        print(f"WARNING: {error}", file=sys.stderr)
    return 0


def _print_enrichment_status() -> None:
    status = get_enrichment_status()
    print(f"Registry CVEs: {status['registry_cve_count']}")
    for source in ("epss", "kev", "nvd"):
        source_status = status[source]
        if source_status["cached"]:
            stale = " (STALE)" if source_status["stale"] else ""
            print(
                f"  {source.upper()}: {source_status['count']} entries, "
                f"{source_status['age_hours']}h old{stale}"
            )
        else:
            print(f"  {source.upper()}: not cached")


def _print_cve_lookup(cve_id: str) -> int:
    enriched = enrich_registry()
    entry = enriched.get(cve_id)
    if entry is None:
        print(f"{cve_id}: not in registry")
        return 1
    print(f"{entry.base.cve_id}: {entry.base.title}")
    print(f"  CVSS:      {entry.base.cvss_score}")
    print(f"  EPSS:      {entry.epss_score or 'N/A'}")
    print(f"  Percentile:{entry.epss_percentile or 'N/A'}")
    print(f"  KEV:       {'Yes' if entry.in_kev else 'No'}")
    if entry.kev_date_added:
        print(f"  KEV Added: {entry.kev_date_added}")
    if entry.kev_ransomware:
        print("  Ransomware: Yes")
    print(f"  Status:    {entry.base.exploitation_status}")
    return 0


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if not any([args.fetch, args.status, args.lookup]):
        parser.print_help()
        return 0

    if args.fetch:
        fetch_exit = _run_fetch(args.force)
        if fetch_exit:
            return fetch_exit

    if args.status:
        _print_enrichment_status()

    if args.lookup:
        return _print_cve_lookup(args.lookup)

    return 0


if __name__ == "__main__":
    sys.exit(main())
