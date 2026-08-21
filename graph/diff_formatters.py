"""diff_formatters.py - Summary and text formatters for Rootstock posture diffs."""

from __future__ import annotations

from diff_models import PostureDiff
from models import ScanResult


# ── Summary statistics ──────────────────────────────────────────────────────

def _count_injectable(scan: ScanResult) -> int:
    return sum(1 for app in scan.applications if app.injection_methods)


def _count_allowed_grants(scan: ScanResult) -> int:
    return sum(1 for grant in scan.tcc_grants if grant.allowed)


def _count_remote_access_changes(diff: PostureDiff) -> int:
    return (
        len(diff.remote_access.added)
        + len(diff.remote_access.removed)
        + len(diff.remote_access.changed)
    )


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
        "remote_access_changes": _count_remote_access_changes(diff),
        "icloud_posture_changes": len(diff.icloud_posture.changes),
    }


# ── Formatters ──────────────────────────────────────────────────────────────

def format_text(diff: PostureDiff, summary: dict) -> str:
    """Format diff as human-readable text."""
    lines = _header_lines(diff)
    lines.extend(_summary_lines(summary))
    lines.extend(_application_lines(diff))
    lines.extend(_tcc_lines(diff))
    lines.extend(_injection_lines(diff))
    lines.extend(_persistence_lines(diff))
    lines.extend(_entitlement_lines(diff))
    lines.extend(_system_posture_lines(diff))
    lines.extend(_physical_posture_lines(diff))
    lines.extend(_remote_access_lines(diff))
    lines.extend(_icloud_posture_lines(diff))
    lines.extend(_vulnerability_lines(diff))
    if _has_no_changes(diff):
        lines.append("No security-relevant changes detected.")
    return "\n".join(lines)


def _header_lines(diff: PostureDiff) -> list[str]:
    return [
        f"Rootstock Posture Diff - {diff.hostname}",
        f"  Before: {diff.before_timestamp} (scan {diff.before_scan_id[:8]})",
        f"  After:  {diff.after_timestamp} (scan {diff.after_scan_id[:8]})",
        "",
    ]


def _summary_lines(summary: dict) -> list[str]:
    lines = ["=== Posture Summary ==="]
    for key in ("apps", "injectable", "tcc_grants", "persistence"):
        before = summary[f"{key}_before"]
        after = summary[f"{key}_after"]
        delta = summary[f"{key}_delta"]
        sign = "+" if delta > 0 else ""
        label = key.replace("_", " ").title()
        lines.append(f"  {label}: {before} → {after} ({sign}{delta})")
    return lines + [""]


def _added_removed_section_lines(
    heading: str,
    added_lines: list[str],
    removed_lines: list[str],
) -> list[str]:
    if not (added_lines or removed_lines):
        return []
    return [heading, *added_lines, *removed_lines, ""]


def _application_lines(diff: PostureDiff) -> list[str]:
    return _added_removed_section_lines(
        "=== Application Changes ===",
        [f"  [+] {app}" for app in diff.apps.added],
        [f"  [-] {app}" for app in diff.apps.removed],
    )


def _tcc_lines(diff: PostureDiff) -> list[str]:
    if not (diff.tcc.added or diff.tcc.removed or diff.tcc.changed):
        return []
    lines = ["=== TCC Grant Changes ==="]
    for grant in diff.tcc.added:
        status = "allowed" if grant["allowed"] else "denied"
        lines.append(f"  [+] {grant['client']} → {grant['service']} ({grant['scope']}, {status})")
    lines.extend(
        f"  [-] {grant['client']} → {grant['service']} ({grant['scope']})"
        for grant in diff.tcc.removed
    )
    lines.extend(
        f"  [~] {grant['client']} → {grant['service']}: "
        f"allowed {grant['before_allowed']} → {grant['after_allowed']}"
        for grant in diff.tcc.changed
    )
    return lines + [""]


def _injection_lines(diff: PostureDiff) -> list[str]:
    if not (
        diff.injection.new_injectable
        or diff.injection.no_longer_injectable
        or diff.injection.methods_changed
    ):
        return []
    lines = ["=== Injection Surface Changes ==="]
    lines.extend(
        f"  [+] {item['name']} ({item['bundle_id']}): {', '.join(item['methods'])} "
        f"[{item['reason']}]"
        for item in diff.injection.new_injectable
    )
    lines.extend(
        f"  [-] {item['name']} ({item['bundle_id']}): was {', '.join(item['methods'])} "
        f"[{item['reason']}]"
        for item in diff.injection.no_longer_injectable
    )
    lines.extend(
        f"  [~] {item['name']}: {item['before']} → {item['after']}"
        for item in diff.injection.methods_changed
    )
    return lines + [""]


def _persistence_lines(diff: PostureDiff) -> list[str]:
    return _added_removed_section_lines(
        "=== Persistence Changes ===",
        [f"  [+] {item}" for item in diff.persistence.added],
        [f"  [-] {item}" for item in diff.persistence.removed],
    )


def _entitlement_lines(diff: PostureDiff) -> list[str]:
    if not (
        diff.entitlements.apps_gained_critical
        or diff.entitlements.apps_lost_critical
    ):
        return []
    lines = ["=== Security-Critical Entitlement Changes ==="]
    lines.extend(
        f"  [+] {item['name']}: gained {', '.join(item['entitlements'])}"
        for item in diff.entitlements.apps_gained_critical
    )
    lines.extend(
        f"  [-] {item['name']}: lost {', '.join(item['entitlements'])}"
        for item in diff.entitlements.apps_lost_critical
    )
    return lines + [""]


def _system_posture_lines(diff: PostureDiff) -> list[str]:
    if not diff.system_posture:
        return []
    lines = ["=== System Posture Changes ==="]
    lines.extend(
        f"  [!] {key}: {change['before']} → {change['after']}"
        for key, change in diff.system_posture.items()
    )
    return lines + [""]


def _physical_posture_lines(diff: PostureDiff) -> list[str]:
    return _added_removed_section_lines(
        "=== Physical Security Posture Changes ===",
        [
            f"  [!] {key.replace('_', ' ').title()}: {change['before']} → {change['after']}"
            for key, change in diff.physical_posture.changes.items()
        ],
        [],
    )


def _remote_access_lines(diff: PostureDiff) -> list[str]:
    if not (
        diff.remote_access.added
        or diff.remote_access.removed
        or diff.remote_access.changed
    ):
        return []
    lines = ["=== Remote Access Changes ==="]
    lines.extend(_remote_added_line(service) for service in diff.remote_access.added)
    lines.extend(f"  [-] {service['service']}" for service in diff.remote_access.removed)
    lines.extend(_remote_changed_line(service) for service in diff.remote_access.changed)
    return lines + [""]


def _remote_added_line(service: dict) -> str:
    status = "enabled" if service["enabled"] else "disabled"
    port_str = f" (port {service['port']})" if service.get("port") else ""
    return f"  [+] {service['service']}: {status}{port_str}"


def _remote_changed_line(service: dict) -> str:
    parts = []
    if "enabled" in service:
        parts.append(f"enabled {service['enabled']['before']} → {service['enabled']['after']}")
    if "port" in service:
        parts.append(f"port {service['port']['before']} → {service['port']['after']}")
    return f"  [~] {service['service']}: {', '.join(parts)}"


def _icloud_posture_lines(diff: PostureDiff) -> list[str]:
    if not diff.icloud_posture.changes:
        return []
    lines = ["=== iCloud Posture Changes ==="]
    lines.extend(
        f"  [!] {key.replace('_', ' ').title()}: {change['before']} → {change['after']}"
        for key, change in diff.icloud_posture.changes.items()
    )
    return lines + [""]


def _vulnerability_lines(diff: PostureDiff) -> list[str]:
    vuln = diff.vulnerability
    if not (
        vuln.new_cve_associations
        or vuln.resolved_cve_associations
        or vuln.new_kev_entries
    ):
        return []
    lines = ["=== Vulnerability Association Changes ==="]
    lines.extend(
        f"  [+] {assoc['app']} ({assoc['bundle_id']}): {assoc.get('cve_id', '?')} "
        f"(CVSS {assoc.get('cvss_score', '?')})"
        for assoc in vuln.new_cve_associations
    )
    lines.extend(
        f"  [-] {assoc['app']} ({assoc['bundle_id']}): {assoc.get('reason', '?')}"
        for assoc in vuln.resolved_cve_associations
    )
    if vuln.new_kev_entries:
        lines.append("  New CISA KEV entries:")
        lines.extend(
            f"    [!] {entry['cve_id']}: {entry.get('title', '?')} "
            f"(added {entry.get('kev_date_added', '?')})"
            for entry in vuln.new_kev_entries
        )
    return lines + [""]


def _has_no_changes(diff: PostureDiff) -> bool:
    vuln = diff.vulnerability
    section_changes = (
        diff.apps.added,
        diff.apps.removed,
        diff.tcc.added,
        diff.tcc.removed,
        diff.tcc.changed,
        diff.injection.new_injectable,
        diff.injection.no_longer_injectable,
        diff.injection.methods_changed,
        diff.persistence.added,
        diff.persistence.removed,
        diff.entitlements.apps_gained_critical,
        diff.entitlements.apps_lost_critical,
        diff.system_posture,
        diff.physical_posture.changes,
        diff.remote_access.added,
        diff.remote_access.removed,
        diff.remote_access.changed,
        diff.icloud_posture.changes,
        vuln.new_cve_associations,
        vuln.resolved_cve_associations,
    )
    return not any(section_changes)
