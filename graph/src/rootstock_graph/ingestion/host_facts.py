"""host_facts.py - Per-scan host facts written onto the scan's Computer node.

FirewallPolicy, RemoteAccessService, SudoersRule and CriticalFile nodes are shared
across scans, so host rules read these Computer properties instead of the nodes.
"""

from __future__ import annotations

from .import_nodes_enrichment import mode_digit_allows_write

PRIVILEGED_FILE_CATEGORIES = (
    "tcc_database",
    "sudoers",
    "launch_daemon_dir",
    "authorization_db",
    "ssh_config",
)


def scan_firewall_enabled(scan) -> bool | None:
    """The application firewall state recorded by this scan (None when not collected)."""
    states = [status.enabled for status in scan.firewall_status]
    return states[0] if states else None


def _service_enabled(scan, name: str) -> bool | None:
    states = [s.enabled for s in scan.remote_access_services if s.service == name]
    return states[0] if states else None


def host_fact_properties(scan) -> dict[str, object]:
    """Firewall, remote access, sudo and file-permission facts of this scan."""
    nopasswd = {(r.user, r.host, r.command) for r in scan.sudoers_rules if r.nopasswd}
    privileged = {
        f.path
        for f in scan.file_acls
        if f.is_writable_by_non_root and f.category in PRIVILEGED_FILE_CATEGORIES
    }
    shell_hooks = {
        f.path
        for f in scan.file_acls
        if f.category == "shell_hook"
        and (mode_digit_allows_write(f.mode, 1) or mode_digit_allows_write(f.mode, 2))
    }
    return {
        "firewall_enabled": scan_firewall_enabled(scan),
        "ssh_enabled": _service_enabled(scan, "ssh"),
        "screen_sharing_enabled": _service_enabled(scan, "screen_sharing"),
        "nopasswd_rule_count": len(nopasswd),
        "writable_privileged_file_count": len(privileged),
        "writable_shell_hook_count": len(shell_hooks),
    }
