"""
infer_recommendations_inventory.py - Recommendation rules for host evidence.

Covers launchd environment injection, stale launch items, network listeners,
browser extensions, account and remote-control settings, Software Update,
custom root certificates, proxies and /etc/hosts. ``infer_recommendations``
appends ``RULES`` to its rule table, so every rule here is merged, linked and
evaluated exactly like the built-in ones. Text is written for the person who
administers the Mac and names the setting or command to use.
"""

from __future__ import annotations

from ..category_predicates import RISK_CATEGORY_PREDICATES
from .recommendation_rule import RecommendationRule

__all__ = ["RULES"]

_SHARING = "System Settings › General › Sharing"
_UPDATES = "System Settings › General › Software Update › Automatic Updates"
_USERS = "System Settings › Users & Groups"

_EXPOSED_LISTENER = (
    "EXISTS { MATCH (app)-[:LISTENS_ON]->(nl:NetworkListener) "
    "WHERE nl.exposed = true AND {firewall} }"
)

RULES: list[RecommendationRule] = [
    # ── Application evidence ────────────────────────────────────────────────
    RecommendationRule(
        "remove_launchd_env_injection",
        "launchd_env_injection",
        "Launch item injects a library with DYLD_* variables",
        "A LaunchDaemon or LaunchAgent belonging to this app sets DYLD_INSERT_LIBRARIES (or "
        "another DYLD_* variable), so launchd loads that library into the program at every "
        "start. Unless the vendor documents it, treat it as tampering: open the plist in "
        "/Library/LaunchDaemons, /Library/LaunchAgents or ~/Library/LaunchAgents, remove the "
        "EnvironmentVariables entry or the whole item, and reinstall the app.",
        "critical",
        ("T1574.006",),
        RISK_CATEGORY_PREDICATES["launchd_env_injection"],
    ),
    RecommendationRule(
        "review_exposed_listener",
        "network_exposed",
        "App accepts network connections while the firewall is off",
        "This app listens for connections from other machines and the application firewall "
        "is off, so anyone on the same network can reach it. Turn on the firewall in System "
        "Settings › Network › Firewall, or stop the service (quit the app or turn off its "
        "server or sharing option) if you do not use it.",
        "high",
        ("T1210",),
        _EXPOSED_LISTENER.replace("{firewall}", "nl.reachable_without_firewall = true"),
    ),
    RecommendationRule(
        "review_listener_firewall_rule",
        "network_exposed",
        "App accepts network connections",
        "This app listens for connections from other machines. The firewall is on, but apps "
        "allowed in System Settings › Network › Firewall › Options still receive them. Set the "
        "app to block incoming connections unless it must be reachable from other machines.",
        "medium",
        ("T1210",),
        _EXPOSED_LISTENER.replace("{firewall}", "nl.firewall_enabled = true"),
    ),
    RecommendationRule(
        "review_browser_extension",
        "browser_extension_risk",
        "Review this browser's extensions",
        "This browser has extensions that can read and change every website together with "
        "permissions such as cookies, webRequest or nativeMessaging, or that were loaded "
        "unpacked (developer mode) or side-loaded by another program (external). Open the "
        "browser's extensions page, remove the ones you do not recognise or use, and prefer "
        "extensions installed from the official store.",
        "medium",
        ("T1176",),
        RISK_CATEGORY_PREDICATES["browser_extension_risk"],
    ),
    # ── Host settings ───────────────────────────────────────────────────────
    RecommendationRule(
        "clean_stale_persistence",
        "persistence",
        "Remove launch items whose program is gone",
        "Launch items point to a program that no longer exists, usually left behind by an "
        "uninstalled app. Whoever can create a file at that path gets it run at the next "
        "start (as root for a LaunchDaemon). Unload the item (`sudo launchctl bootout "
        "system/<label>` for a daemon) and delete its plist from /Library/LaunchDaemons, "
        "/Library/LaunchAgents or ~/Library/LaunchAgents.",
        "low",
        ("T1543.004",),
        "c.stale_launch_item_count > 0",
        target="host",
    ),
    RecommendationRule(
        "disable_guest_account",
        "host_posture",
        "Turn off the guest account",
        f"Anyone at the Mac can sign in as Guest without a password. Turn it off in {_USERS} › "
        "Guest User.",
        "medium",
        ("T1078.001",),
        "c.guest_account_enabled = true",
        target="host",
    ),
    RecommendationRule(
        "disable_auto_login",
        "host_posture",
        "Turn off automatic login",
        "The Mac signs a user in at start-up without asking for a password, so anyone who "
        "restarts it gets that account, its files and its unlocked keychain. Set "
        f"{_USERS} › Automatically log in as to Off (turning on FileVault also disables it).",
        "high",
        ("T1078",),
        "c.auto_login_user IS NOT NULL",
        target="host",
    ),
    RecommendationRule(
        "disable_root_account",
        "host_posture",
        "Disable the root account",
        "The root user has a password and can sign in directly, which bypasses the admin "
        "prompts and audit trail of sudo. Run `sudo dsenableroot -d` (or Directory Utility › "
        "Edit › Disable Root User).",
        "high",
        ("T1078.003",),
        "c.root_account_enabled = true",
        target="host",
    ),
    RecommendationRule(
        "disable_remote_apple_events",
        "lateral_movement",
        "Remote Apple Events are on",
        "Other Macs can send Apple Events to apps on this Mac and script them remotely. Turn "
        f"off Remote Application Scripting in {_SHARING} unless you rely on it.",
        "medium",
        ("T1021",),
        "c.remote_apple_events_enabled = true",
        target="host",
    ),
    RecommendationRule(
        "disable_remote_management",
        "lateral_movement",
        "Remote Management is on",
        "Apple Remote Desktop can observe and control this Mac. Turn off Remote Management in "
        f"{_SHARING} unless your organization uses it; if it does, allow only specific users.",
        "medium",
        ("T1021.005",),
        "c.remote_management_enabled = true",
        target="host",
    ),
    RecommendationRule(
        "enable_security_responses",
        "host_posture",
        "Install security responses automatically",
        "Rapid Security Responses and XProtect / system data updates are not installed "
        f"automatically, so malware signatures and urgent fixes arrive late. In {_UPDATES} "
        "turn on Install Security Responses and system files.",
        "high",
        ("T1562.001",),
        "c.software_update_install_security_responses = false",
        target="host",
    ),
    RecommendationRule(
        "enable_automatic_updates",
        "host_posture",
        "Turn on automatic macOS updates",
        "Software Update does not check for or install macOS updates on its own, so security "
        f"fixes depend on someone remembering. In {_UPDATES} turn on Check for updates and "
        "Install macOS updates.",
        "medium",
        (),
        "c.software_update_install_system_updates = false "
        "OR c.software_update_automatic_check = false",
        target="host",
    ),
    RecommendationRule(
        "review_custom_root_cas",
        "host_posture",
        "Review custom root certificates",
        "A root certificate added by a user or administrator is trusted, so whoever holds its "
        "key can issue certificates for any website and read encrypted traffic. In Keychain "
        "Access › System (admin) or login (user) › Certificates, delete roots your "
        "organization did not install for a proxy or MDM.",
        "high",
        ("T1553.004",),
        "EXISTS { MATCH (c)-[:TRUSTS_CERTIFICATE]->(:TrustedCertificate {custom_root: true}) }",
        target="host",
    ),
    RecommendationRule(
        "review_proxy_settings",
        "host_posture",
        "Confirm the proxy settings",
        "Web traffic is sent through a proxy or an automatic proxy configuration (PAC) file. "
        "That is normal on managed networks; if you did not set it up, remove it in System "
        "Settings › Network › (service) › Details › Proxies.",
        "low",
        ("T1090",),
        "c.proxy_count > 0",
        target="host",
    ),
    RecommendationRule(
        "review_hosts_file",
        "host_posture",
        "Review /etc/hosts entries",
        "/etc/hosts overrides DNS for some names, which can send you to a different server "
        "than the real one. Check each entry with `cat /etc/hosts` and remove the ones you did "
        "not add (`sudo nano /etc/hosts`).",
        "low",
        ("T1565.001",),
        "c.hosts_entry_count > 0",
        target="host",
    ),
]
