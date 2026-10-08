"""Attach per-product NVD coverage so zero known matches cannot imply full coverage."""

from __future__ import annotations

from ..vulnerability.nvd_installed import MACOS_TARGET_ID, match_set_status


def import_cve_coverage(session, scan, selection, found: dict) -> None:
    session.run(
        """
        MATCH (a {scan_id: $scan_id})
        WHERE a:Application OR a:Computer
        SET a.nvd_coverage = CASE WHEN a:Computer THEN 'not_assessed' WHEN a.is_system THEN 'system_component_not_matched' ELSE 'uncatalogued' END,
            a.nvd_target_count = 0, a.nvd_cached_count = 0,
            a.nvd_cache_stale = null, a.nvd_cache_complete = null,
            a.nvd_cache_truncated = null
        """,
        scan_id=scan.scan_id,
    )
    grouped: dict[tuple[str, str], list] = {}
    for target in selection.targets:
        grouped.setdefault((target.bundle_id, target.version), []).append(target)
    for (bundle_id, version), targets in grouped.items():
        statuses = [
            match_set_status(found[target.cpe_name])
            for target in targets
            if target.cpe_name in found
        ]
        props = {
            "nvd_coverage": "cached"
            if len(statuses) == len(targets)
            else "partial_cache"
            if statuses
            else "not_cached",
            "nvd_target_count": len(targets),
            "nvd_cached_count": len(statuses),
            "nvd_cache_stale": any(status["stale"] for status in statuses) if statuses else None,
            "nvd_cache_complete": all(
                status["complete"] is True and not status["requires_refresh"] for status in statuses
            )
            if len(statuses) == len(targets)
            else False,
            "nvd_cache_truncated": any(status["truncated"] for status in statuses)
            if statuses
            else None,
        }
        match = (
            "MATCH (subject:Computer {scan_id: $scan_id})"
            if bundle_id == MACOS_TARGET_ID
            else (
                "MATCH (subject:Application {scan_id: $scan_id, bundle_id: $bundle_id, version: $version})"
            )
        )
        session.run(
            match + " SET subject += $props",
            scan_id=scan.scan_id,
            bundle_id=bundle_id,
            version=version,
            props=props,
        )
    for bundle_id, _reason in selection.skipped:
        match = (
            "MATCH (subject:Computer {scan_id: $scan_id})"
            if bundle_id == MACOS_TARGET_ID
            else (
                "MATCH (subject:Application {scan_id: $scan_id, bundle_id: $bundle_id}) "
                "WHERE subject.nvd_target_count = 0 AND coalesce(subject.is_system, false) = false"
            )
        )
        session.run(
            match + " SET subject.nvd_coverage = 'skipped_version'",
            scan_id=scan.scan_id,
            bundle_id=bundle_id,
        )
