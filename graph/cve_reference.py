"""
cve_reference.py - CVE and MITRE ATT&CK reference registry for Rootstock findings.

Maps Rootstock finding categories to real-world CVEs (2023-2025) and ATT&CK techniques,
enabling prioritised vulnerability context in reports.
"""

from __future__ import annotations

import re

from cve_reference_catalog import _GROUP_REGISTRY, _GROUP_TECHNIQUE_MAP, _REGISTRY
from cve_reference_models import (
    AttackContext,
    AttackTechnique,
    CveEntry,
    CweReference,
    ThreatGroup,
)

# Registry version - bump when CVE/ATT&CK/CWE entries are added or modified.
# Imported by import_vulnerabilities.py and embedded in graph metadata.
REGISTRY_VERSION = "2026-03-21"

_VALID_EXPLOITATION_STATUSES = {"actively_exploited", "poc_available", "theoretical"}
_VALID_ATTACK_COMPLEXITIES = {"low", "medium", "high"}


__all__ = [
    "AttackContext",
    "AttackTechnique",
    "CWE_REGISTRY",
    "CveEntry",
    "CweReference",
    "REGISTRY_VERSION",
    "ThreatGroup",
    "_GROUP_REGISTRY",
    "_GROUP_TECHNIQUE_MAP",
    "_REGISTRY",
    "_VALID_ATTACK_COMPLEXITIES",
    "_VALID_EXPLOITATION_STATUSES",
    "get_all_critical_cves",
    "get_context",
    "get_contexts_for_query",
    "get_cwe",
    "get_cwe_summary",
]


# ── Public API ────────────────────────────────────────────────────────────────

_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d+")


def get_context(category: str) -> AttackContext | None:
    """Return the AttackContext for a finding category, or None if unknown."""
    return _REGISTRY.get(category)


def get_contexts_for_query(query: dict) -> list[AttackContext]:
    """
    Return AttackContexts relevant to a query descriptor.

    Looks up by CVE IDs in the query's ``cve`` field, matching against
    all registry entries.
    """
    cve_field = query.get("cve", "")
    if not cve_field:
        return []

    query_cves = set(_CVE_ID_RE.findall(cve_field))
    if not query_cves:
        return []

    matches: list[AttackContext] = []
    for ctx in _REGISTRY.values():
        ctx_cves = {c.cve_id for c in ctx.cves}
        if ctx_cves & query_cves:
            matches.append(ctx)
    return matches


def get_all_critical_cves(min_cvss: float = 8.0) -> list[CveEntry]:
    """Return all CVEs at or above min_cvss, sorted by CVSS descending."""
    seen: set[str] = set()
    result: list[CveEntry] = []
    for ctx in _REGISTRY.values():
        for cve in ctx.cves:
            if cve.cvss_score >= min_cvss and cve.cve_id not in seen:
                seen.add(cve.cve_id)
                result.append(cve)
    result.sort(key=lambda c: c.cvss_score, reverse=True)
    return result


# ── CWE Reference Lookup ────────────────────────────────────────────────────

# Master CWE reference table - maps CWE IDs to human-readable names.
CWE_REGISTRY: dict[str, CweReference] = {
    "CWE-20":  CweReference("CWE-20",  "Improper Input Validation",                      "input_validation"),
    "CWE-22":  CweReference("CWE-22",  "Path Traversal",                                 "input_validation"),
    "CWE-59":  CweReference("CWE-59",  "Improper Link Resolution Before File Access",    "input_validation"),
    "CWE-120": CweReference("CWE-120", "Buffer Overflow",                                "memory_safety"),
    "CWE-122": CweReference("CWE-122", "Heap-based Buffer Overflow",                     "memory_safety"),
    "CWE-200": CweReference("CWE-200", "Exposure of Sensitive Information",               "information_disclosure"),
    "CWE-269": CweReference("CWE-269", "Improper Privilege Management",                   "access_control"),
    "CWE-276": CweReference("CWE-276", "Incorrect Default Permissions",                   "access_control"),
    "CWE-284": CweReference("CWE-284", "Improper Access Control",                         "access_control"),
    "CWE-287": CweReference("CWE-287", "Improper Authentication",                         "authentication"),
    "CWE-347": CweReference("CWE-347", "Improper Verification of Cryptographic Signature","authentication"),
    "CWE-362": CweReference("CWE-362", "Race Condition",                                  "concurrency"),
    "CWE-416": CweReference("CWE-416", "Use After Free",                                  "memory_safety"),
    "CWE-427": CweReference("CWE-427", "Uncontrolled Search Path Element",                "input_validation"),
    "CWE-668": CweReference("CWE-668", "Exposure of Resource to Wrong Sphere",            "access_control"),
    "CWE-693": CweReference("CWE-693", "Protection Mechanism Failure",                    "access_control"),
    "CWE-787": CweReference("CWE-787", "Out-of-bounds Write",                             "memory_safety"),
    "CWE-862": CweReference("CWE-862", "Missing Authorization",                           "access_control"),
    "CWE-863": CweReference("CWE-863", "Incorrect Authorization",                         "access_control"),
}


def get_cwe(cwe_id: str) -> CweReference | None:
    """Look up a CWE reference by ID."""
    return CWE_REGISTRY.get(cwe_id)


def get_cwe_summary() -> dict[str, int]:
    """Count CWE occurrences across all registry CVEs. Returns {cwe_id: count}."""
    counts: dict[str, int] = {}
    seen: set[str] = set()
    for ctx in _REGISTRY.values():
        for cve in ctx.cves:
            if cve.cve_id in seen:
                continue
            seen.add(cve.cve_id)
            for cwe_id in cve.cwe_ids:
                counts[cwe_id] = counts.get(cwe_id, 0) + 1
    return counts
