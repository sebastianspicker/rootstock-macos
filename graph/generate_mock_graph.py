#!/usr/bin/env python3
"""Build OpenGraph JSON from demo-scan.json without Neo4j."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from constants import (
    ATTACKER_BUNDLE_ID,
    ATTACKER_NAME,
    FDA_SERVICE,
    APPLE_EVENTS_SERVICE,
    ACCESSIBILITY_SERVICE,
    SCREEN_CAPTURE_SERVICE,
    CAMERA_SERVICE,
    MICROPHONE_SERVICE,
)
from opengraph_export import NODE_TYPE_MAP, EDGE_TYPE_MAP, make_node_id
from viewer_layout import compute_layout


TCC_DISPLAY = {
    "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
    "kTCCServiceCamera": "Camera",
    "kTCCServiceMicrophone": "Microphone",
    "kTCCServiceScreenCapture": "Screen Recording",
    "kTCCServiceAccessibility": "Accessibility",
    "kTCCServiceAppleEvents": "Automation (Apple Events)",
    "kTCCServiceAddressBook": "Contacts",
    "kTCCServiceCalendar": "Calendar",
    "kTCCServicePhotos": "Photos",
}


def _make_node(hostname: str, label: str, key: str, display_name: str,
               extra_props: dict | None = None) -> dict:
    type_info = NODE_TYPE_MAP[label]
    props = {"_icon": type_info["icon"], "_color": type_info["color"]}
    if extra_props:
        props.update(extra_props)
    return {
        "id": make_node_id(hostname, label, key),
        "kind": type_info["kind"],
        "label": display_name,
        "properties": props,
    }


def _make_edge(hostname: str, src_label: str, src_key: str,
               tgt_label: str, tgt_key: str,
               rel_type: str, extra_props: dict | None = None) -> dict:
    type_info = EDGE_TYPE_MAP[rel_type]
    props = {"_traversable": type_info["traversable"]}
    if extra_props:
        props.update(extra_props)
    return {
        "source": make_node_id(hostname, src_label, src_key),
        "target": make_node_id(hostname, tgt_label, tgt_key),
        "kind": type_info["kind"],
        "properties": props,
    }


def build_mock_graph(scan: dict) -> dict:
    """Transform scan JSON into OpenGraph JSON with inferred edges."""
    hostname = scan.get("hostname", "rootstock-demo")
    nodes: list[dict] = []
    edges: list[dict] = []
    node_ids: set[str] = set()

    def add_node(n: dict) -> None:
        if n["id"] not in node_ids:
            nodes.append(n)
            node_ids.add(n["id"])

    add_node(_make_node(hostname, "Computer", hostname, hostname, {
        "hostname": hostname,
        "macos_version": scan.get("macos_version", ""),
        "scan_id": scan.get("scan_id", ""),
    }))

    # Applications
    apps_by_bid: dict[str, dict] = {}
    for app in scan.get("applications", []):
        bid = app["bundle_id"]
        apps_by_bid[bid] = app
        is_injectable = bool(app.get("injection_methods"))

        risk_score = 0
        if is_injectable:
            risk_score += 40
        if app.get("is_electron"):
            risk_score += 15
        if not app.get("hardened_runtime"):
            risk_score += 10
        if not app.get("library_validation"):
            risk_score += 10

        add_node(_make_node(hostname, "Application", bid, app["name"], {
            "bundle_id": bid,
            "name": app["name"],
            "path": app.get("path", ""),
            "team_id": app.get("team_id", ""),
            "hardened_runtime": app.get("hardened_runtime", False),
            "library_validation": app.get("library_validation", False),
            "is_electron": app.get("is_electron", False),
            "signed": app.get("signed", True),
            "is_system": app.get("is_system", False),
            "injection_methods": app.get("injection_methods", []),
            "risk_score": risk_score,
        }))

        edges.append(_make_edge(hostname, "Application", bid,
                            "Computer", hostname, "INSTALLED_ON"))

        seen_ents: set[str] = set()
        for ent in app.get("entitlements", []):
            ent_name = ent["name"]
            if ent_name not in seen_ents:
                seen_ents.add(ent_name)
                add_node(_make_node(hostname, "Entitlement", ent_name, ent_name, {
                    "name": ent_name,
                    "is_private": ent.get("is_private", False),
                    "category": ent.get("category", ""),
                    "is_security_critical": ent.get("is_security_critical", False),
                }))
            edges.append(_make_edge(hostname, "Application", bid,
                                "Entitlement", ent_name, "HAS_ENTITLEMENT"))

    # TCC Permissions
    tcc_services: set[str] = set()
    for grant in scan.get("tcc_grants", []):
        service = grant["service"]
        client = grant["client"]
        allowed = grant.get("auth_value", 0) in (2, 3)
        if not allowed:
            continue

        if service not in tcc_services:
            tcc_services.add(service)
            display = TCC_DISPLAY.get(service, service)
            add_node(_make_node(hostname, "TCC_Permission", service, display, {
                "service": service,
                "display_name": display,
            }))

        if client in apps_by_bid:
            edges.append(_make_edge(hostname, "Application", client,
                                "TCC_Permission", service, "HAS_TCC_GRANT", {
                                    "auth_reason": grant.get("auth_reason", 1),
                                    "scope": grant.get("scope", "user"),
                                }))

    for xpc in scan.get("xpc_services", []):
        label = xpc.get("label", xpc.get("identifier", "unknown"))
        add_node(_make_node(hostname, "XPC_Service", label, label, {
            "label": label,
            "type": xpc.get("type", ""),
            "run_as_user": xpc.get("run_as_user", ""),
            "has_client_verification": xpc.get("has_client_verification", False),
        }))
        # Link XPC to apps that share a team/bundle prefix
        for bid, app in apps_by_bid.items():
            if label.startswith(bid.rsplit(".", 1)[0]):
                edges.append(_make_edge(hostname, "Application", bid,
                                    "XPC_Service", label, "COMMUNICATES_WITH"))

    for item in scan.get("launch_items", []):
        label = item.get("label", "unknown")
        add_node(_make_node(hostname, "LaunchItem", label, label, {
            "label": label,
            "type": item.get("type", ""),
            "run_as_user": item.get("run_as_user", "root"),
            "plist_writable_by_non_root": item.get("plist_writable_by_non_root", False),
        }))
        # Link apps that persist via launch items
        for bid in apps_by_bid:
            if label.startswith(bid.rsplit(".", 1)[0]):
                edges.append(_make_edge(hostname, "Application", bid,
                                    "LaunchItem", label, "PERSISTS_VIA"))

    for kc in scan.get("keychain_acls", []):
        kc_label = kc.get("label", "unknown")
        kc_kind = kc.get("kind", "generic_password")
        kc_key = f"{kc_label}-{kc_kind}"
        add_node(_make_node(hostname, "Keychain_Item", kc_key, kc_label, {
            "label": kc_label,
            "kind": kc_kind,
            "access_group": kc.get("access_group", ""),
        }))
        for trusted_bid in kc.get("trusted_apps", []):
            if trusted_bid in apps_by_bid:
                edges.append(_make_edge(hostname, "Application", trusted_bid,
                                    "Keychain_Item", kc_key, "CAN_READ_KEYCHAIN"))

    for user in scan.get("user_details", []):
        uname = user.get("name", "unknown")
        add_node(_make_node(hostname, "User", uname, uname, {
            "name": uname,
            "home": user.get("home", ""),
            "shell": user.get("shell", ""),
        }))
        if not user.get("is_hidden", False):
            for bid, app in apps_by_bid.items():
                if not app.get("is_system", False):
                    edges.append(_make_edge(hostname, "Application", bid,
                                        "User", uname, "RUNS_AS"))

    for group in scan.get("local_groups", []):
        gname = group.get("name", "unknown")
        add_node(_make_node(hostname, "LocalGroup", gname, gname, {
            "name": gname,
            "gid": group.get("gid", -1),
        }))
        for member in group.get("members", []):
            uid = make_node_id(hostname, "User", member)
            if uid in node_ids:
                edges.append(_make_edge(hostname, "User", member,
                                    "LocalGroup", gname, "MEMBER_OF"))

    for f in scan.get("file_acls", []):
        fpath = f.get("path", "unknown")
        fname = fpath.rsplit("/", 1)[-1]
        add_node(_make_node(hostname, "CriticalFile", fpath, fname, {
            "path": fpath,
            "owner": f.get("owner", ""),
            "group": f.get("group_owner", ""),
            "mode": f.get("mode", ""),
            "is_writable_by_non_root": f.get("is_writable_by_non_root", False),
        }))

    for ext in scan.get("system_extensions", []):
        eid = ext.get("identifier", "unknown")
        add_node(_make_node(hostname, "SystemExtension", eid, eid, {
            "identifier": eid,
            "type": ext.get("type", ""),
            "enabled": ext.get("enabled", True),
        }))

    add_node(_make_node(hostname, "Application", ATTACKER_BUNDLE_ID, ATTACKER_NAME, {
        "bundle_id": ATTACKER_BUNDLE_ID,
        "name": ATTACKER_NAME,
        "owned": True,
        "risk_score": 0,
        "tier": "Attacker",
    }))

    # Inferred edges
    for bid, app in apps_by_bid.items():
        if app.get("injection_methods"):
            edges.append(_make_edge(hostname, "Application", ATTACKER_BUNDLE_ID,
                                "Application", bid, "CAN_INJECT_INTO", {
                                    "methods": app["injection_methods"],
                                }))

    for bid, app in apps_by_bid.items():
        if app.get("is_electron") and app.get("injection_methods"):
            for grant in scan.get("tcc_grants", []):
                if grant["client"] == bid and grant.get("auth_value", 0) in (2, 3):
                    edges.append(_make_edge(hostname, "Application", bid,
                                        "TCC_Permission", grant["service"],
                                        "CHILD_INHERITS_TCC"))

    for grant in scan.get("tcc_grants", []):
        if grant["service"] == APPLE_EVENTS_SERVICE:
            client = grant["client"]
            # Apple Events client can automate Finder
            finder_bid = "com.apple.finder"
            if client in apps_by_bid and finder_bid in apps_by_bid:
                edges.append(_make_edge(hostname, "Application", client,
                                    "Application", finder_bid, "CAN_SEND_APPLE_EVENT"))
                # Transitive FDA: if Finder has FDA
                if any(g["client"] == finder_bid and g["service"] == FDA_SERVICE
                       for g in scan.get("tcc_grants", [])):
                    edges.append(_make_edge(hostname, "Application", client,
                                        "TCC_Permission", FDA_SERVICE, "HAS_TRANSITIVE_FDA"))

    for item in scan.get("launch_items", []):
        if item.get("plist_writable_by_non_root"):
            label = item.get("label", "unknown")
            edges.append(_make_edge(hostname, "Application", ATTACKER_BUNDLE_ID,
                                "LaunchItem", label, "CAN_HIJACK"))

    for rule in scan.get("sudoers_rules", []):
        if rule.get("nopasswd"):
            uname = rule.get("user", "unknown")
            uid = make_node_id(hostname, "User", uname)
            key = f"{uname}-ALL"
            add_node(_make_node(hostname, "SudoersRule", key, f"sudo NOPASSWD ({uname})", {
                "key": key,
                "user": uname,
                "nopasswd": True,
            }))
            if uid in node_ids:
                edges.append(_make_edge(hostname, "User", uname,
                                    "SudoersRule", key, "SUDO_NOPASSWD"))

    # Synthesised nodes
    vulns = [
        {
            "cve_id": "CVE-2024-44133",
            "title": "TCC Bypass via DYLD Injection",
            "cvss_score": 7.8,
            "affected_bids": ["com.googlecode.iterm2"],
        },
        {
            "cve_id": "CVE-2024-44168",
            "title": "Library Validation Bypass",
            "cvss_score": 7.1,
            "affected_bids": ["com.googlecode.iterm2", "org.mozilla.firefox"],
        },
        {
            "cve_id": "CVE-2023-44402",
            "title": "Electron ELECTRON_RUN_AS_NODE Abuse",
            "cvss_score": 7.8,
            "affected_bids": ["com.tinyspeck.slackmacgap", "com.microsoft.VSCode",
                              "com.1password.1password"],
        },
        {
            "cve_id": "CVE-2024-44206",
            "title": "Apple Events TCC Bypass",
            "cvss_score": 6.5,
            "affected_bids": ["com.omnigroup.OmniGraffle7"],
        },
    ]
    for vuln in vulns:
        cve = vuln["cve_id"]
        add_node(_make_node(hostname, "Vulnerability", cve, cve, {
            "cve_id": cve,
            "title": vuln["title"],
            "cvss_score": vuln["cvss_score"],
            "epss_score": round(0.15 + hash(cve) % 50 / 100, 2),
        }))
        for bid in vuln["affected_bids"]:
            if bid in apps_by_bid:
                edges.append(_make_edge(hostname, "Application", bid,
                                    "Vulnerability", cve, "AFFECTED_BY"))

    techniques = [
        {"technique_id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
        {"technique_id": "T1059.004", "name": "Unix Shell", "tactic": "Execution"},
        {"technique_id": "T1548.003", "name": "Sudo and Sudo Caching", "tactic": "Privilege Escalation"},
    ]
    for tech in techniques:
        tid = tech["technique_id"]
        add_node(_make_node(hostname, "AttackTechnique", tid, f"{tid}: {tech['name']}", {
            "technique_id": tid,
            "name": tech["name"],
            "tactic": tech["tactic"],
        }))
    vuln_tech_links = [
        ("CVE-2024-44133", "T1055"),
        ("CVE-2024-44168", "T1055"),
        ("CVE-2023-44402", "T1059.004"),
        ("CVE-2024-44206", "T1059.004"),
    ]
    for cve, tid in vuln_tech_links:
        edges.append(_make_edge(hostname, "Vulnerability", cve,
                            "AttackTechnique", tid, "MAPS_TO_TECHNIQUE"))

    recommendations = [
        {"key": "enable-hardened-runtime",
         "title": "Enable Hardened Runtime for in-house apps",
         "category": "injectable_fda", "priority": "critical"},
        {"key": "disable-electron-run-as-node",
         "title": "Disable ELECTRON_RUN_AS_NODE in production Electron builds",
         "category": "electron_inheritance", "priority": "high"},
        {"key": "audit-apple-events",
         "title": "Audit Apple Event automation TCC grants",
         "category": "apple_events", "priority": "high"},
        {"key": "enable-filevault",
         "title": "Enable FileVault full-disk encryption",
         "category": "physical_security", "priority": "medium"},
    ]
    for rec in recommendations:
        rkey = rec["key"]
        add_node(_make_node(hostname, "Recommendation", rkey, rec["title"], {
            "key": rkey,
            "title": rec["title"],
            "category": rec["category"],
            "priority": rec["priority"],
        }))

    # Tier assignment
    for n in nodes:
        if n["kind"] != NODE_TYPE_MAP["Application"]["kind"]:
            continue
        bid = n["properties"].get("bundle_id", "")
        if bid == ATTACKER_BUNDLE_ID:
            continue
        app = apps_by_bid.get(bid)
        if not app:
            continue

        has_fda = any(
            g["client"] == bid and g["service"] == FDA_SERVICE
            and g.get("auth_value", 0) in (2, 3)
            for g in scan.get("tcc_grants", [])
        )
        has_high_tcc = any(
            g["client"] == bid
            and g["service"] in (ACCESSIBILITY_SERVICE, SCREEN_CAPTURE_SERVICE,
                                 CAMERA_SERVICE, MICROPHONE_SERVICE)
            and g.get("auth_value", 0) in (2, 3)
            for g in scan.get("tcc_grants", [])
        )
        is_injectable = bool(app.get("injection_methods"))

        if has_fda and is_injectable:
            n["properties"]["tier"] = "Tier 0"
            n["properties"]["risk_score"] = min(100, n["properties"].get("risk_score", 0) + 35)
        elif has_fda or (has_high_tcc and is_injectable):
            n["properties"]["tier"] = "Tier 1"
            n["properties"]["risk_score"] = min(100, n["properties"].get("risk_score", 0) + 20)
        elif has_high_tcc or is_injectable:
            n["properties"]["tier"] = "Tier 2"
        else:
            n["properties"]["tier"] = "Tier 3"

    print(f"Computing layout for {len(nodes)} nodes, {len(edges)} edges...", end=" ", flush=True)
    compute_layout(nodes, edges, iterations=250)
    print("done.")

    return {
        "metadata": {
            "source_kind": "Rootstock",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "hostname": hostname,
            "node_count": len(nodes),
            "edge_count": len(edges),
        },
        "graph": {
            "nodes": nodes,
            "edges": edges,
        },
    }


# CLI

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build OpenGraph JSON from demo-scan.json (no Neo4j required)"
    )
    parser.add_argument("--scan", "-s", default=None,
                        help="Scan JSON file (default: examples/demo-scan.json)")
    parser.add_argument("--output", "-o", required=True,
                        help="Output OpenGraph JSON file")
    args = parser.parse_args()

    scan_path = Path(args.scan) if args.scan else Path(__file__).parent.parent / "examples" / "demo-scan.json"
    if not scan_path.exists():
        print(f"ERROR: Scan file not found: {scan_path}", file=sys.stderr)
        return 1

    scan = json.loads(scan_path.read_text())
    graph = build_mock_graph(scan)

    output_path = Path(args.output)
    output_path.write_text(json.dumps(graph, indent=2) + "\n")
    print(f"Wrote {graph['metadata']['node_count']} nodes, "
          f"{graph['metadata']['edge_count']} edges to {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
