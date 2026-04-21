#!/usr/bin/env python3
"""
diff_scans.py — Compare two Rootstock scans of the same host to track posture changes.

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

This is the "posture trending" capability — transforms Rootstock from a
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
    before_map = {}
    for g in before.tcc_grants:
        key = _tcc_key(g.service, g.client, g.scope)
        before_map[key] = g

    after_map = {}
    for g in after.tcc_grants:
        key = _tcc_key(g.service, g.client, g.scope)
        after_map[key] = g

    before_keys = set(before_map)
    after_keys = set(after_map)

    added = []
    for key in sorted(after_keys - before_keys):
        g = after_map[key]
        added.append({
            "client": g.client,
            "service": g.service,
            "scope": g.scope,
            "allowed": g.allowed,
        })

    removed = []
    for key in sorted(before_keys - after_keys):
        g = before_map[key]
        removed.append({
            "client": g.client,
            "service": g.service,
            "scope": g.scope,
            "allowed": g.allowed,
        })

    changed = []
    for key in sorted(before_keys & after_keys):
        bg = before_map[key]
        ag = after_map[key]
        if bg.auth_value != ag.auth_value:
            changed.append({
                "client": ag.client,
                "service": ag.service,
                "scope": ag.scope,
                "before_auth_value": bg.auth_value,
                "after_auth_value": ag.auth_value,
                "before_allowed": bg.allowed,
                "after_allowed": ag.allowed,
            })

    return TCCDiff(added=added, removed=removed, changed=changed)


def diff_injection(before: ScanResult, after: ScanResult) -> InjectionDiff:
    """Compare injection surface changes."""
    before_map = {a.bundle_id: a for a in before.applications}
    after_map = {a.bundle_id: a for a in after.applications}

    common = set(before_map) & set(after_map)
    new_injectable = []
    no_longer = []
    methods_changed = []

    # New apps that are injectable
    for bid in set(after_map) - set(before_map):
        app = after_map[bid]
        if app.injection_methods:
            new_injectable.append({
                "bundle_id": bid,
                "name": app.name,
                "methods": list(app.injection_methods),
                "reason": "new_app",
            })

    # Removed apps that were injectable
    for bid in set(before_map) - set(after_map):
        app = before_map[bid]
        if app.injection_methods:
            no_longer.append({
                "bundle_id": bid,
                "name": app.name,
                "methods": list(app.injection_methods),
                "reason": "app_removed",
            })

    # Existing apps with changed injection surface
    for bid in common:
        ba = before_map[bid]
        aa = after_map[bid]
        before_methods = set(ba.injection_methods)
        after_methods = set(aa.injection_methods)

        if not before_methods and after_methods:
            new_injectable.append({
                "bundle_id": bid,
                "name": aa.name,
                "methods": list(aa.injection_methods),
                "reason": "became_injectable",
            })
        elif before_methods and not after_methods:
            no_longer.append({
                "bundle_id": bid,
                "name": aa.name,
                "methods": list(ba.injection_methods),
                "reason": "fixed",
            })
        elif before_methods != after_methods:
            methods_changed.append({
                "bundle_id": bid,
                "name": aa.name,
                "before": sorted(before_methods),
                "after": sorted(after_methods),
            })

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

    added = []
    for key in sorted(after_keys - before_keys):
        s = after_map[key]
        added.append({"service": s.service, "enabled": s.enabled, "port": s.port})

    removed = []
    for key in sorted(before_keys - after_keys):
        s = before_map[key]
        removed.append({"service": s.service, "enabled": s.enabled, "port": s.port})

    changed = []
    for key in sorted(before_keys & after_keys):
        bs = before_map[key]
        a_s = after_map[key]
        diffs: dict[str, dict] = {}
        if bs.enabled != a_s.enabled:
            diffs["enabled"] = {"before": bs.enabled, "after": a_s.enabled}
        if bs.port != a_s.port:
            diffs["port"] = {"before": bs.port, "after": a_s.port}
        if diffs:
            changed.append({"service": key, **diffs})

    return RemoteAccessDiff(added=added, removed=removed, changed=changed)


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
    try:
        from cve_enrichment import enrich_registry
        from cve_reference import _REGISTRY  # noqa: F401
    except ImportError:
        return VulnerabilityDiff()

    enriched = enrich_registry()
    if not enriched:
        return VulnerabilityDiff()

    # Build per-app injectable status for before/after
    before_injectable = {a.bundle_id for a in before.applications if a.injection_methods}
    after_injectable = {a.bundle_id for a in after.applications if a.injection_methods}

    # Apps that became injectable gain CVE associations
    newly_injectable = after_injectable - before_injectable
    no_longer_injectable = before_injectable - after_injectable

    after_names = {a.bundle_id: a.name for a in after.applications}
    before_names = {a.bundle_id: a.name for a in before.applications}

    new_associations: list[dict] = []
    resolved_associations: list[dict] = []

    # Build a set of CVE IDs relevant to injection-related categories
    injection_related_categories = {
        "injectable_fda", "dyld_injection", "tcc_bypass",
        "blastpass_class", "running_processes",
    }
    injection_cve_ids: set[str] = set()
    for cat, ctx in _REGISTRY.items():
        if cat in injection_related_categories:
            for cve in ctx.cves:
                injection_cve_ids.add(cve.cve_id)

    for bid in newly_injectable:
        name = after_names.get(bid, bid)
        for cve_id, entry in enriched.items():
            # Only associate CVEs from injection-relevant categories
            if cve_id not in injection_cve_ids:
                continue
            new_associations.append({
                "app": name,
                "bundle_id": bid,
                "cve_id": entry.base.cve_id,
                "cvss_score": entry.base.cvss_score,
                "reason": "app_became_injectable",
            })

    for bid in no_longer_injectable:
        name = before_names.get(bid, bid)
        resolved_associations.append({
            "app": name,
            "bundle_id": bid,
            "reason": "app_no_longer_injectable",
        })

    # Check for new KEV entries (CVEs added to KEV since last scan)
    new_kev: list[dict] = []
    for cve_id, entry in enriched.items():
        if entry.in_kev and entry.kev_date_added:
            new_kev.append({
                "cve_id": cve_id,
                "title": entry.base.title,
                "kev_date_added": entry.kev_date_added,
            })

    return VulnerabilityDiff(
        new_cve_associations=new_associations[:50],  # Cap to avoid huge diffs
        resolved_cve_associations=resolved_associations[:50],
        new_kev_entries=new_kev,
    )


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

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare two Rootstock scans to track posture changes"
    )
    parser.add_argument("--before", required=True, help="Earlier scan JSON file")
    parser.add_argument("--after", required=True, help="Later scan JSON file")
    parser.add_argument("--format", choices=["text", "json"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--output", "-o", help="Write output to file (default: stdout)")
    args = parser.parse_args()

    before_path = Path(args.before)
    after_path = Path(args.after)

    for p in (before_path, after_path):
        if not p.exists():
            print(f"ERROR: File not found: {p}", file=sys.stderr)
            return 1

    before = load_scan(before_path)
    if before is None:
        return 1

    after = load_scan(after_path)
    if after is None:
        return 1

    # Warn if hostnames differ
    if before.hostname != after.hostname:
        print(
            f"WARNING: Hostnames differ: '{before.hostname}' vs '{after.hostname}'. "
            "Diff results may not be meaningful for different hosts.",
            file=sys.stderr,
        )

    diff = diff_scans(before, after)
    summary = summarize(diff, before, after)

    if args.format == "json":
        output_data = {
            "summary": summary,
            "diff": asdict(diff),
        }
        output = json.dumps(output_data, indent=2) + "\n"
    else:
        output = format_text(diff, summary) + "\n"

    if args.output:
        Path(args.output).write_text(output)
        print(f"Diff written to {args.output}")
    else:
        print(output, end="")

    return 0


if __name__ == "__main__":
    sys.exit(main())
