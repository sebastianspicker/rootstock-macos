"""Offline CVE candidates with per-target cache and catalogue coverage."""

from __future__ import annotations

from ..models import ScanResult
from ..vulnerability.nvd_installed import (
    MACOS_TARGET_ID,
    cached_installed_matches,
    enrich_installed_matches,
    match_set_status,
    select_cpe_targets,
)
from .detections import finding
from .evidence import stable_id


def cve_evidence(
    scan: ScanResult, nodes: dict[str, dict], links: list[dict]
) -> tuple[list[dict], list[dict]]:
    selection = select_cpe_targets(scan)
    cached, _ = cached_installed_matches(selection.targets)
    signals = enrich_installed_matches({m.cve_id for s in cached.values() for m in s.matches})
    coverage, findings = [], []
    for target in selection.targets:
        match_set = cached.get(target.cpe_name)
        status = match_set_status(match_set) if match_set else {}
        coverage.append(
            {
                "bundle_id": target.bundle_id,
                "name": target.name,
                "version": target.version,
                "cpe": target.cpe_name,
                "status": "cached" if match_set else "not_cached",
                **status,
                "retained_matches": len(match_set.matches) if match_set else None,
                "total_matched": match_set.total_matched if match_set else None,
            }
        )
        if not match_set:
            continue
        subjects = [
            node
            for node in list(nodes.values())
            if (
                node["kind"] == "host"
                if target.bundle_id == MACOS_TARGET_ID
                else node["kind"] == "applications"
                and node["facts"]["bundle_id"] == target.bundle_id
                and node["facts"]["version"] == target.version
            )
        ]
        for match in match_set.matches:
            key = stable_id("cve_match", target.cpe_name, match.cve_id)
            signal = signals[match.cve_id]
            nodes[key] = {
                "id": key,
                "kind": "cve_match",
                "source": "nvd_installed_cache",
                "source_pointer": None,
                "scan_id": scan.scan_id,
                "facts": match.to_dict()
                | status
                | {
                    "cpe": target.cpe_name,
                    "in_cached_kev": signal.in_kev,
                    "kev_fetched_at": signal.kev_fetched_at,
                    "kev_stale": signal.kev_stale,
                    "epss_fetched_at": signal.epss_fetched_at,
                    "epss_stale": signal.epss_stale,
                    "epss": signal.epss_score,
                    "signal_note": "Cached KEV/EPSS may be incomplete or stale; absence is not a negative finding",
                },
            }
            for subject in subjects:
                links.append(
                    {
                        "source": subject["id"],
                        "target": key,
                        "relation": "cve_candidate",
                        "classification": "inference",
                        "basis": match.matched_criteria,
                    }
                )
                current = not status["stale"] and not status["requires_refresh"]
                verified_range = match.applicability == "version_match" and current
                priority = (
                    "high"
                    if verified_range and (signal.in_kev or (match.cvss_score or 0) >= 7)
                    else "medium"
                )
                findings.append(
                    finding(
                        "cve." + match.cve_id,
                        subject,
                        priority,
                        f"{target.name}: review {match.cve_id}",
                        f"Installed version {target.version} matches cached NVD criteria. "
                        f"Applicability: {match.applicability}. "
                        + ("Cache requires refresh. " if not current else "")
                        + "Product/version matching does not establish exploitability.",
                        "Review the vendor advisory and required conditions; verify the installed build and supported update.",
                        confidence="conditional" if not verified_range else "version_match",
                        related=(key,),
                    )
                )
    coverage.extend(_unmatched_coverage(scan, selection))
    return coverage, _deduplicate(findings)


def _unmatched_coverage(scan, selection) -> list[dict]:
    coverage = []
    for bundle_id, name, version in selection.uncatalogued:
        coverage.append(
            {"bundle_id": bundle_id, "name": name, "version": version, "status": "uncatalogued"}
        )
    for bundle_id, reason in selection.skipped:
        coverage.append({"bundle_id": bundle_id, "status": "skipped", "reason": reason})
    system_apps = sum(app.is_system for app in scan.applications)
    if system_apps:
        coverage.append(
            {
                "status": "system_apps_not_individually_matched",
                "count": system_apps,
                "reason": "Only the host macOS release is selected; this is not coverage of every system component",
            }
        )
    return coverage


def _deduplicate(findings: list[dict]) -> list[dict]:
    # Multiple CPE aliases for a product can establish the same CVE candidate.
    unique = {}
    for row in findings:
        prior = unique.get(row["id"])
        if prior:
            evidence = sorted(set(prior["evidence_ids"] + row["evidence_ids"]))
            if row["confidence"] == "version_match":
                unique[row["id"]] = row
            unique[row["id"]]["evidence_ids"] = evidence
        else:
            unique[row["id"]] = row
    return list(unique.values())
