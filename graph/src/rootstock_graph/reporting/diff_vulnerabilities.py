"""Vulnerability-association comparison for scan posture diffs."""

from __future__ import annotations

from ..models import ScanResult
from .diff_models import VulnerabilityDiff


def diff_vulnerabilities(before: ScanResult, after: ScanResult) -> VulnerabilityDiff:
    """Compare vulnerability associations between scans.

    Uses the enriched CVE registry to determine which apps gained or lost
    CVE associations based on changes in their injection surface, TCC grants,
    and other properties that drive category matching.
    """
    loaded = _load_vulnerability_diff_registry()
    if loaded is None:
        return VulnerabilityDiff()
    enriched, registry = loaded

    before_injectable = {a.bundle_id for a in before.applications if a.injection_methods}
    after_injectable = {a.bundle_id for a in after.applications if a.injection_methods}

    after_names = {a.bundle_id: a.name for a in after.applications}
    before_names = {a.bundle_id: a.name for a in before.applications}

    new_associations = _new_injection_cve_associations(
        sorted(after_injectable - before_injectable),
        after_names,
        enriched,
        _injection_cve_ids(registry),
    )
    return VulnerabilityDiff(
        new_cve_associations=new_associations[:50],
        resolved_cve_associations=_resolved_injection_cve_associations(
            sorted(before_injectable - after_injectable),
            before_names,
        )[:50],
        new_kev_entries=_new_kev_entries(
            enriched,
            {a.bundle_id for a in after.applications},
            {a.bundle_id for a in before.applications},
            {assoc["cve_id"] for assoc in new_associations},
        ),
    )


def _load_vulnerability_diff_registry() -> tuple[dict, dict] | None:
    try:
        from ..vulnerability.cve_enrichment import enrich_registry
        from ..vulnerability.cve_reference_catalog import REGISTRY
    except ImportError:
        return None

    enriched = enrich_registry()
    if not enriched:
        return None
    return enriched, REGISTRY


def _injection_cve_ids(registry: dict) -> set[str]:
    injection_related_categories = {
        "injectable_fda",
        "dyld_injection",
        "tcc_bypass",
        "blastpass_class",
        "running_processes",
    }
    return {
        cve.cve_id
        for category, context in registry.items()
        if category in injection_related_categories
        for cve in context.cves
    }


def _new_injection_cve_associations(
    newly_injectable: list[str],
    after_names: dict[str, str],
    enriched: dict,
    injection_cve_ids: set[str],
) -> list[dict]:
    associations: list[dict] = []
    for bundle_id in newly_injectable:
        name = after_names.get(bundle_id, bundle_id)
        for cve_id, entry in enriched.items():
            if cve_id in injection_cve_ids:
                associations.append(
                    {
                        "app": name,
                        "bundle_id": bundle_id,
                        "cve_id": entry.base.cve_id,
                        "cvss_score": entry.base.cvss_score,
                        "reason": "app_became_injectable",
                    }
                )
    return associations


def _resolved_injection_cve_associations(
    no_longer_injectable: list[str],
    before_names: dict[str, str],
) -> list[dict]:
    return [
        {
            "app": before_names.get(bundle_id, bundle_id),
            "bundle_id": bundle_id,
            "reason": "app_no_longer_injectable",
        }
        for bundle_id in no_longer_injectable
    ]


def _new_kev_entries(
    enriched: dict,
    after_bundle_ids: set[str],
    before_bundle_ids: set[str],
    associated_cve_ids: set[str],
) -> list[dict]:
    """List KEV CVEs that became relevant between the two scans, sorted by CVE id.

    A KEV CVE is included when its registry entry names an affected bundle id
    that is present in the newer scan but was absent from the older one, or when
    the diff already associates it with a newly injectable app
    (``associated_cve_ids``).
    """
    return [
        {
            "cve_id": cve_id,
            "title": entry.base.title,
            "kev_date_added": entry.kev_date_added,
        }
        for cve_id, entry in sorted(enriched.items())
        if entry.in_kev
        and entry.kev_date_added
        and (
            cve_id in associated_cve_ids
            or (
                after_bundle_ids.intersection(entry.base.affected_bundle_ids)
                and not before_bundle_ids.intersection(entry.base.affected_bundle_ids)
            )
        )
    ]
