"""diff_formatters.py — Summary and text formatters for Rootstock posture diffs."""

from __future__ import annotations

from diff_models import PostureDiff
from models import ScanResult


# ── Summary statistics ──────────────────────────────────────────────────────

def _count_injectable(scan: ScanResult) -> int:
    return sum(1 for a in scan.applications if a.injection_methods)


def _count_allowed_grants(scan: ScanResult) -> int:
    return sum(1 for g in scan.tcc_grants if g.allowed)


def summarize(diff: PostureDiff, before: ScanResult, after: ScanResult) -> dict:
    """Generate a high-level summary with posture delta metrics."""
    injectable_before = _count_injectable(before)
    injectable_after = _count_injectable(after)
    grants_before = _count_allowed_grants(before)
    grants_after = _count_allowed_grants(after)

    return {
        "apps_before": len(before.applications),
        "apps_after": len(after.applications),
        "apps_delta": len(after.applications) - len(before.applications),
        "injectable_before": injectable_before,
        "injectable_after": injectable_after,
        "injectable_delta": injectable_after - injectable_before,
        "tcc_grants_before": grants_before,
        "tcc_grants_after": grants_after,
        "tcc_grants_delta": grants_after - grants_before,
        "persistence_before": len(before.launch_items),
        "persistence_after": len(after.launch_items),
        "persistence_delta": len(after.launch_items) - len(before.launch_items),
        "new_tcc_grants": len(diff.tcc.added),
        "removed_tcc_grants": len(diff.tcc.removed),
        "changed_tcc_grants": len(diff.tcc.changed),
        "new_injectable_apps": len(diff.injection.new_injectable),
        "fixed_injectable_apps": len(diff.injection.no_longer_injectable),
        "physical_posture_changes": len(diff.physical_posture.changes),
        "remote_access_changes": (
            len(diff.remote_access.added)
            + len(diff.remote_access.removed)
            + len(diff.remote_access.changed)
        ),
        "icloud_posture_changes": len(diff.icloud_posture.changes),
    }


# ── Formatters ──────────────────────────────────────────────────────────────

def format_text(diff: PostureDiff, summary: dict) -> str:
    """Format diff as human-readable text."""
    lines = []
    lines.append(f"Rootstock Posture Diff — {diff.hostname}")
    lines.append(f"  Before: {diff.before_timestamp} (scan {diff.before_scan_id[:8]})")
    lines.append(f"  After:  {diff.after_timestamp} (scan {diff.after_scan_id[:8]})")
    lines.append("")

    # Summary metrics
    lines.append("=== Posture Summary ===")
    for key in ("apps", "injectable", "tcc_grants", "persistence"):
        b = summary[f"{key}_before"]
        a = summary[f"{key}_after"]
        d = summary[f"{key}_delta"]
        sign = "+" if d > 0 else ""
        label = key.replace("_", " ").title()
        lines.append(f"  {label}: {b} → {a} ({sign}{d})")
    lines.append("")

    # Applications
    if diff.apps.added or diff.apps.removed:
        lines.append("=== Application Changes ===")
        for a in diff.apps.added:
            lines.append(f"  [+] {a}")
        for r in diff.apps.removed:
            lines.append(f"  [-] {r}")
        lines.append("")

    # TCC grants
    if diff.tcc.added or diff.tcc.removed or diff.tcc.changed:
        lines.append("=== TCC Grant Changes ===")
        for g in diff.tcc.added:
            status = "allowed" if g["allowed"] else "denied"
            lines.append(f"  [+] {g['client']} → {g['service']} ({g['scope']}, {status})")
        for g in diff.tcc.removed:
            lines.append(f"  [-] {g['client']} → {g['service']} ({g['scope']})")
        for g in diff.tcc.changed:
            lines.append(
                f"  [~] {g['client']} → {g['service']}: "
                f"allowed {g['before_allowed']} → {g['after_allowed']}"
            )
        lines.append("")

    # Injection surface
    if diff.injection.new_injectable or diff.injection.no_longer_injectable or diff.injection.methods_changed:
        lines.append("=== Injection Surface Changes ===")
        for i in diff.injection.new_injectable:
            lines.append(f"  [+] {i['name']} ({i['bundle_id']}): {', '.join(i['methods'])} [{i['reason']}]")
        for i in diff.injection.no_longer_injectable:
            lines.append(f"  [-] {i['name']} ({i['bundle_id']}): was {', '.join(i['methods'])} [{i['reason']}]")
        for i in diff.injection.methods_changed:
            lines.append(f"  [~] {i['name']}: {i['before']} → {i['after']}")
        lines.append("")

    # Persistence
    if diff.persistence.added or diff.persistence.removed:
        lines.append("=== Persistence Changes ===")
        for p in diff.persistence.added:
            lines.append(f"  [+] {p}")
        for p in diff.persistence.removed:
            lines.append(f"  [-] {p}")
        lines.append("")

    # Entitlements
    if diff.entitlements.apps_gained_critical or diff.entitlements.apps_lost_critical:
        lines.append("=== Security-Critical Entitlement Changes ===")
        for e in diff.entitlements.apps_gained_critical:
            lines.append(f"  [+] {e['name']}: gained {', '.join(e['entitlements'])}")
        for e in diff.entitlements.apps_lost_critical:
            lines.append(f"  [-] {e['name']}: lost {', '.join(e['entitlements'])}")
        lines.append("")

    # System posture
    if diff.system_posture:
        lines.append("=== System Posture Changes ===")
        for key, change in diff.system_posture.items():
            lines.append(f"  [!] {key}: {change['before']} → {change['after']}")
        lines.append("")

    # Physical security posture
    if diff.physical_posture.changes:
        lines.append("=== Physical Security Posture Changes ===")
        for key, change in diff.physical_posture.changes.items():
            label = key.replace("_", " ").title()
            lines.append(f"  [!] {label}: {change['before']} → {change['after']}")
        lines.append("")

    # Remote access
    if diff.remote_access.added or diff.remote_access.removed or diff.remote_access.changed:
        lines.append("=== Remote Access Changes ===")
        for s in diff.remote_access.added:
            status = "enabled" if s["enabled"] else "disabled"
            port_str = f" (port {s['port']})" if s.get("port") else ""
            lines.append(f"  [+] {s['service']}: {status}{port_str}")
        for s in diff.remote_access.removed:
            lines.append(f"  [-] {s['service']}")
        for s in diff.remote_access.changed:
            parts = []
            if "enabled" in s:
                parts.append(f"enabled {s['enabled']['before']} → {s['enabled']['after']}")
            if "port" in s:
                parts.append(f"port {s['port']['before']} → {s['port']['after']}")
            lines.append(f"  [~] {s['service']}: {', '.join(parts)}")
        lines.append("")

    # iCloud posture
    if diff.icloud_posture.changes:
        lines.append("=== iCloud Posture Changes ===")
        for key, change in diff.icloud_posture.changes.items():
            label = key.replace("_", " ").title()
            lines.append(f"  [!] {label}: {change['before']} → {change['after']}")
        lines.append("")

    # Vulnerability changes
    vuln = diff.vulnerability
    if vuln.new_cve_associations or vuln.resolved_cve_associations or vuln.new_kev_entries:
        lines.append("=== Vulnerability Association Changes ===")
        for a in vuln.new_cve_associations:
            lines.append(f"  [+] {a['app']} ({a['bundle_id']}): {a.get('cve_id', '?')} (CVSS {a.get('cvss_score', '?')})")
        for a in vuln.resolved_cve_associations:
            lines.append(f"  [-] {a['app']} ({a['bundle_id']}): {a.get('reason', '?')}")
        if vuln.new_kev_entries:
            lines.append("  New CISA KEV entries:")
            for k in vuln.new_kev_entries:
                lines.append(f"    [!] {k['cve_id']}: {k.get('title', '?')} (added {k.get('kev_date_added', '?')})")
        lines.append("")

    # No changes
    all_empty = (
        not diff.apps.added and not diff.apps.removed
        and not diff.tcc.added and not diff.tcc.removed and not diff.tcc.changed
        and not diff.injection.new_injectable and not diff.injection.no_longer_injectable
        and not diff.injection.methods_changed
        and not diff.persistence.added and not diff.persistence.removed
        and not diff.entitlements.apps_gained_critical and not diff.entitlements.apps_lost_critical
        and not diff.system_posture
        and not diff.physical_posture.changes
        and not diff.remote_access.added and not diff.remote_access.removed and not diff.remote_access.changed
        and not diff.icloud_posture.changes
        and not vuln.new_cve_associations and not vuln.resolved_cve_associations
    )
    if all_empty:
        lines.append("No security-relevant changes detected.")

    return "\n".join(lines)
