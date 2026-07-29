#!/usr/bin/env python3
"""
diff_scans.py - Compare two Rootstock scans of the same host to track posture changes.

Takes two scan JSON files (same host, different dates) and reports:
  - New / removed applications
  - New / removed TCC grants
  - Changed injection surface (new injectable apps, fixed apps)
  - New / closed attack paths (shortest-path-to-FDA comparison)
  - Entitlement changes
  - Persistence changes
  - Physical security posture changes
  - Remote access service changes
  - iCloud posture changes

This is the "posture trending" capability - transforms Rootstock from a
point-in-time tool into an operational monitoring platform.

Usage:
    python3 graph/diff_scans.py --before scan-2026-03-01.json --after scan-2026-03-15.json
    python3 graph/diff_scans.py --before old.json --after new.json --format json --output diff.json

Exit code 0 on success, 1 on failure.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from models import ScanResult

from scan_loader import load_scan


from diff_models import (  # noqa: F401
    AppDiff,
    TCCDiff,
    InjectionDiff,
    PersistenceDiff,
    EntitlementDiff,
    PhysicalPostureDiff,
    RemoteAccessDiff,
    ICloudPostureDiff,
    VulnerabilityDiff,
    PostureDiff,
)

from diff_formatters import (  # noqa: F401
    summarize,
    format_text,
)


# ── Diff logic ──────────────────────────────────────────────────────────────

def _tcc_key(service: str, client: str, scope: str) -> str:
    return f"{client}|{service}|{scope}"


def _tcc_grant_map(grants) -> dict[str, object]:
    return {_tcc_key(g.service, g.client, g.scope): g for g in grants}


def _tcc_grant_row(grant) -> dict:
    return {
        "client": grant.client,
        "service": grant.service,
        "scope": grant.scope,
        "allowed": grant.allowed,
    }


def _changed_tcc_row(before_grant, after_grant) -> dict:
    return {
        "client": after_grant.client,
        "service": after_grant.service,
        "scope": after_grant.scope,
        "before_auth_value": before_grant.auth_value,
        "after_auth_value": after_grant.auth_value,
        "before_allowed": before_grant.allowed,
        "after_allowed": after_grant.allowed,
    }


def _injection_row(bundle_id: str, app, methods, *, reason: str) -> dict:
    return {
        "bundle_id": bundle_id,
        "name": app.name,
        "methods": list(methods),
        "reason": reason,
    }


def _new_or_removed_injection_rows(
    app_map: dict,
    bundle_ids: set[str],
    *,
    reason: str,
) -> list[dict]:
    rows = []
    for bundle_id in bundle_ids:
        app = app_map[bundle_id]
        if app.injection_methods:
            rows.append(
                _injection_row(
                    bundle_id,
                    app,
                    app.injection_methods,
                    reason=reason,
                )
            )
    return rows


def _changed_injection_rows(before_map: dict, after_map: dict, common: set[str]) -> tuple[list[dict], list[dict], list[dict]]:
    new_injectable = []
    no_longer = []
    methods_changed = []
    for bundle_id in common:
        before_app = before_map[bundle_id]
        after_app = after_map[bundle_id]
        before_methods = set(before_app.injection_methods)
        after_methods = set(after_app.injection_methods)

        if not before_methods and after_methods:
            new_injectable.append(
                _injection_row(bundle_id, after_app, after_app.injection_methods, reason="became_injectable")
            )
        elif before_methods and not after_methods:
            no_longer.append(_injection_row(bundle_id, after_app, before_app.injection_methods, reason="fixed"))
        elif before_methods != after_methods:
            methods_changed.append({
                "bundle_id": bundle_id,
                "name": after_app.name,
                "before": sorted(before_methods),
                "after": sorted(after_methods),
            })
    return new_injectable, no_longer, methods_changed


def diff_apps(before: ScanResult, after: ScanResult) -> AppDiff:
    """Compare application inventories."""
    before_ids = {a.bundle_id for a in before.applications}
    after_ids = {a.bundle_id for a in after.applications}
    after_names = {a.bundle_id: a.name for a in after.applications}
    before_names = {a.bundle_id: a.name for a in before.applications}

    return AppDiff(
        added=[f"{bid} ({after_names.get(bid, '?')})" for bid in sorted(after_ids - before_ids)],
        removed=[f"{bid} ({before_names.get(bid, '?')})" for bid in sorted(before_ids - after_ids)],
    )


def diff_tcc(before: ScanResult, after: ScanResult) -> TCCDiff:
    """Compare TCC grant changes."""
    before_map = _tcc_grant_map(before.tcc_grants)
    after_map = _tcc_grant_map(after.tcc_grants)

    before_keys = set(before_map)
    after_keys = set(after_map)

    added = []
    for key in sorted(after_keys - before_keys):
        added.append(_tcc_grant_row(after_map[key]))

    removed = []
    for key in sorted(before_keys - after_keys):
        removed.append(_tcc_grant_row(before_map[key]))

    changed = []
    for key in sorted(before_keys & after_keys):
        bg = before_map[key]
        ag = after_map[key]
        if bg.auth_value != ag.auth_value:
            changed.append(_changed_tcc_row(bg, ag))

    return TCCDiff(added=added, removed=removed, changed=changed)


def diff_injection(before: ScanResult, after: ScanResult) -> InjectionDiff:
    """Compare injection surface changes."""
    before_map = {a.bundle_id: a for a in before.applications}
    after_map = {a.bundle_id: a for a in after.applications}

    common = set(before_map) & set(after_map)
    new_injectable = _new_or_removed_injection_rows(
        after_map,
        set(after_map) - set(before_map),
        reason="new_app",
    )
    no_longer = _new_or_removed_injection_rows(
        before_map,
        set(before_map) - set(after_map),
        reason="app_removed",
    )
    changed_new, changed_fixed, methods_changed = _changed_injection_rows(
        before_map,
        after_map,
        common,
    )
    new_injectable.extend(changed_new)
    no_longer.extend(changed_fixed)

    return InjectionDiff(
        new_injectable=new_injectable,
        no_longer_injectable=no_longer,
        methods_changed=methods_changed,
    )


def diff_persistence(before: ScanResult, after: ScanResult) -> PersistenceDiff:
    """Compare persistence mechanism changes."""
    before_labels = {i.label for i in before.launch_items}
    after_labels = {i.label for i in after.launch_items}

    return PersistenceDiff(
        added=sorted(after_labels - before_labels),
        removed=sorted(before_labels - after_labels),
    )


def diff_entitlements(before: ScanResult, after: ScanResult) -> EntitlementDiff:
    """Compare security-critical entitlement changes."""
    def _critical_ents(scan: ScanResult) -> dict[str, set[str]]:
        result: dict[str, set[str]] = {}
        for app in scan.applications:
            crit = {e.name for e in app.entitlements if e.is_security_critical}
            if crit:
                result[app.bundle_id] = crit
        return result

    before_ents = _critical_ents(before)
    after_ents = _critical_ents(after)
    after_names = {a.bundle_id: a.name for a in after.applications}
    before_names = {a.bundle_id: a.name for a in before.applications}

    gained = []
    lost = []

    all_bids = set(before_ents) | set(after_ents)
    for bid in sorted(all_bids):
        be = before_ents.get(bid, set())
        ae = after_ents.get(bid, set())
        name = after_names.get(bid, before_names.get(bid, bid))
        new_ents = ae - be
        removed_ents = be - ae
        if new_ents:
            gained.append({"bundle_id": bid, "name": name, "entitlements": sorted(new_ents)})
        if removed_ents:
            lost.append({"bundle_id": bid, "name": name, "entitlements": sorted(removed_ents)})

    return EntitlementDiff(apps_gained_critical=gained, apps_lost_critical=lost)


def _diff_fields(before: ScanResult, after: ScanResult, field_names: tuple[str, ...]) -> dict[str, dict]:
    """Compare named fields between two scans, returning only changed fields."""
    changes: dict[str, dict] = {}
    for field_name in field_names:
        bv = getattr(before, field_name, None)
        av = getattr(after, field_name, None)
        if bv != av:
            changes[field_name] = {"before": bv, "after": av}
    return changes


def diff_system_posture(before: ScanResult, after: ScanResult) -> dict:
    """Compare system-level security posture flags."""
    return _diff_fields(before, after, ("sip_enabled", "gatekeeper_enabled", "filevault_enabled", "lockdown_mode_enabled"))


def diff_physical_posture(before: ScanResult, after: ScanResult) -> PhysicalPostureDiff:
    """Compare physical security posture fields."""
    return PhysicalPostureDiff(changes=_diff_fields(before, after, (
        "bluetooth_enabled",
        "bluetooth_discoverable",
        "screen_lock_enabled",
        "screen_lock_delay",
        "display_sleep_timeout",
        "thunderbolt_security_level",
        "secure_boot_level",
        "external_boot_allowed",
    )))


def diff_remote_access(before: ScanResult, after: ScanResult) -> RemoteAccessDiff:
    """Compare remote access service changes."""
    before_map = {s.service: s for s in before.remote_access_services}
    after_map = {s.service: s for s in after.remote_access_services}
    before_keys = set(before_map)
    after_keys = set(after_map)

    return RemoteAccessDiff(
        added=_remote_access_rows(after_map, after_keys - before_keys),
        removed=_remote_access_rows(before_map, before_keys - after_keys),
        changed=_changed_remote_access_rows(before_map, after_map, before_keys & after_keys),
    )


def _remote_access_rows(service_map: dict, service_names: set[str]) -> list[dict]:
    return [_remote_access_row(service_map[name]) for name in sorted(service_names)]


def _remote_access_row(service) -> dict:
    return {"service": service.service, "enabled": service.enabled, "port": service.port}


def _changed_remote_access_rows(
    before_map: dict,
    after_map: dict,
    service_names: set[str],
) -> list[dict]:
    changed = []
    for name in sorted(service_names):
        diffs = _changed_remote_access_fields(before_map[name], after_map[name])
        if diffs:
            changed.append({"service": name, **diffs})
    return changed


def _changed_remote_access_fields(before_service, after_service) -> dict[str, dict]:
    diffs: dict[str, dict] = {}
    if before_service.enabled != after_service.enabled:
        diffs["enabled"] = {
            "before": before_service.enabled,
            "after": after_service.enabled,
        }
    if before_service.port != after_service.port:
        diffs["port"] = {"before": before_service.port, "after": after_service.port}
    return diffs


def diff_icloud_posture(before: ScanResult, after: ScanResult) -> ICloudPostureDiff:
    """Compare iCloud posture fields."""
    return ICloudPostureDiff(changes=_diff_fields(before, after, (
        "icloud_signed_in", "icloud_drive_enabled", "icloud_keychain_enabled",
    )))


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

    return VulnerabilityDiff(
        new_cve_associations=_new_injection_cve_associations(
            after_injectable - before_injectable,
            after_names,
            enriched,
            _injection_cve_ids(registry),
        )[:50],
        resolved_cve_associations=_resolved_injection_cve_associations(
            before_injectable - after_injectable,
            before_names,
        )[:50],
        new_kev_entries=_new_kev_entries(enriched),
    )


def _load_vulnerability_diff_registry() -> tuple[dict, dict] | None:
    try:
        from cve_enrichment import enrich_registry
        from cve_reference import _REGISTRY
    except ImportError:
        return None

    enriched = enrich_registry()
    if not enriched:
        return None
    return enriched, _REGISTRY


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
    newly_injectable: set[str],
    after_names: dict[str, str],
    enriched: dict,
    injection_cve_ids: set[str],
) -> list[dict]:
    associations: list[dict] = []
    for bundle_id in newly_injectable:
        name = after_names.get(bundle_id, bundle_id)
        for cve_id, entry in enriched.items():
            if cve_id in injection_cve_ids:
                associations.append({
                    "app": name,
                    "bundle_id": bundle_id,
                    "cve_id": entry.base.cve_id,
                    "cvss_score": entry.base.cvss_score,
                    "reason": "app_became_injectable",
                })
    return associations


def _resolved_injection_cve_associations(
    no_longer_injectable: set[str],
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


def _new_kev_entries(enriched: dict) -> list[dict]:
    return [
        {
            "cve_id": cve_id,
            "title": entry.base.title,
            "kev_date_added": entry.kev_date_added,
        }
        for cve_id, entry in enriched.items()
        if entry.in_kev and entry.kev_date_added
    ]


def diff_scans(before: ScanResult, after: ScanResult) -> PostureDiff:
    """Compute the full posture diff between two scans."""
    return PostureDiff(
        hostname=after.hostname,
        before_scan_id=before.scan_id,
        after_scan_id=after.scan_id,
        before_timestamp=before.timestamp,
        after_timestamp=after.timestamp,
        apps=diff_apps(before, after),
        tcc=diff_tcc(before, after),
        injection=diff_injection(before, after),
        persistence=diff_persistence(before, after),
        entitlements=diff_entitlements(before, after),
        system_posture=diff_system_posture(before, after),
        physical_posture=diff_physical_posture(before, after),
        remote_access=diff_remote_access(before, after),
        icloud_posture=diff_icloud_posture(before, after),
        vulnerability=diff_vulnerabilities(before, after),
    )


# ── CLI ─────────────────────────────────────────────────────────────────────

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare two Rootstock scans to track posture changes"
    )
    parser.add_argument("--before", required=True, help="Earlier scan JSON file")
    parser.add_argument("--after", required=True, help="Later scan JSON file")
    parser.add_argument("--format", choices=["text", "json"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--output", "-o", help="Write output to file (default: stdout)")
    return parser.parse_args(argv)


def _load_diff_inputs(args: argparse.Namespace) -> tuple[ScanResult, ScanResult] | None:
    before_path = Path(args.before)
    after_path = Path(args.after)

    for p in (before_path, after_path):
        if not p.exists():
            print(f"ERROR: File not found: {p}", file=sys.stderr)
            return None

    before = load_scan(before_path)
    if before is None:
        return None

    after = load_scan(after_path)
    if after is None:
        return None
    return before, after


def _warn_if_hostnames_differ(before: ScanResult, after: ScanResult) -> None:
    if before.hostname != after.hostname:
        print(
            f"WARNING: Hostnames differ: '{before.hostname}' vs '{after.hostname}'. "
            "Diff results may not be meaningful for different hosts.",
            file=sys.stderr,
        )


def _format_diff_output(args: argparse.Namespace, before: ScanResult, after: ScanResult) -> str:
    diff = diff_scans(before, after)
    summary = summarize(diff, before, after)

    if args.format == "json":
        output_data = {
            "summary": summary,
            "diff": asdict(diff),
        }
        return json.dumps(output_data, indent=2) + "\n"
    return format_text(diff, summary) + "\n"


def _write_diff_output(args: argparse.Namespace, output: str) -> None:
    if args.output:
        Path(args.output).write_text(output)
        print(f"Diff written to {args.output}")
    else:
        print(output, end="")


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    scans = _load_diff_inputs(args)
    if scans is None:
        return 1
    before, after = scans
    _warn_if_hostnames_differ(before, after)
    output = _format_diff_output(args, before, after)
    _write_diff_output(args, output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
