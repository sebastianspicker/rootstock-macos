"""Assemble a reproducible investigation document from a validated scan."""

from __future__ import annotations

from collections import Counter

from ..models import ScanResult
from .baseline import compare_evidence, validate_baseline, change_findings
from .cves import cve_evidence
from .detections import RULESET_VERSION, detect
from .evidence import evidence_graph


def investigate(scan: ScanResult, baseline: ScanResult | None = None) -> dict:
    nodes, links, coverage = evidence_graph(scan)
    findings = detect(nodes, links)
    warnings = [
        "Review priorities are triage guidance, not malware verdicts or proof of exploitation",
        "A scan is a non-atomic snapshot; path and PID associations are not execution attribution",
        "Legacy scan coverage is incomplete: empty collections and missing values remain unknown",
    ]
    comparison = None
    if baseline:
        warnings.extend(validate_baseline(baseline, scan))
        old_nodes, old_links, _ = evidence_graph(baseline)
        # Same host established by UUID, or accepted hostname fallback: align host identity.
        old_host = next(key for key, node in old_nodes.items() if node["kind"] == "host")
        new_host = next(key for key, node in nodes.items() if node["kind"] == "host")
        if old_host != new_host:
            old_nodes[new_host] = old_nodes.pop(old_host) | {"id": new_host}
        old_findings = {row["id"] for row in detect(old_nodes, old_links)}
        for row in findings:
            row["baseline_status"] = (
                "previously_observed" if row["id"] in old_findings else "newly_observed"
            )
        comparison = compare_evidence(old_nodes, nodes)
        comparison["scan_id"] = baseline.scan_id
        findings.extend(change_findings(comparison, nodes))
    cve_coverage, cve_findings = cve_evidence(scan, nodes, links)
    for row in cve_findings:
        row["baseline_status"] = "not_compared_historical_cache_unavailable"
    findings.extend(cve_findings)
    rank = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda row: (rank[row["priority"]], row["title"], row["id"]))
    return {
        "schema_version": "rootstock-investigation/1",
        "ruleset_version": RULESET_VERSION,
        "scan": {
            "scan_id": scan.scan_id,
            "hostname": scan.hostname,
            "timestamp": scan.timestamp,
            "hardware_uuid": scan.hardware_uuid,
            "collector_version": scan.collector_version,
            "macos_version": scan.macos_version,
            "elevation": scan.elevation.model_dump(),
        },
        "summary": {
            "findings": len(findings),
            "priorities": dict(Counter(row["priority"] for row in findings)),
            "evidence_records": len(nodes),
            "relationships": len(links),
        },
        "limitations": warnings,
        "collection_errors": [error.model_dump() for error in scan.errors],
        "coverage": coverage,
        "cve_coverage": cve_coverage,
        "findings": findings,
        "evidence": list(nodes.values()),
        "relationships": links,
        "baseline": comparison,
    }
