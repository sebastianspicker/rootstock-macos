#!/usr/bin/env python3
"""
opengraph_export.py — Export Rootstock graph data as BloodHound OpenGraph JSON.

Queries Neo4j and produces a JSON file compatible with BloodHound CE v8+
OpenGraph ingest format. Upload via: Administration > File Ingest > Upload.

Usage:
    python3 graph/opengraph_export.py --neo4j bolt://localhost:7687 --output rootstock-opengraph.json
    python3 graph/opengraph_export.py --neo4j bolt://localhost:7687 --output cross.json --cross-domain
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from neo4j_connection import add_neo4j_args, connect_from_args
from constants import NODE_KEY_PROPERTY


# ── Node type mapping ───────────────────────────────────────────────────────

# Node colors optimized for dark backgrounds with high distinguishability.
# Each category uses a distinct hue to aid rapid visual identification:
#   Blue spectrum  = infrastructure (apps, computers, services)
#   Red spectrum   = threats & vulnerabilities
#   Green spectrum = services & sessions
#   Yellow/Orange  = persistence & escalation
#   Purple         = identity & certificates
#   Teal/Cyan      = security controls
NODE_TYPE_MAP: dict[str, dict] = {
    "Application": {"kind": "rs_Application", "icon": "fa-apple", "color": "#58a6ff"},
    "TCC_Permission": {
        "kind": "rs_TCCPermission",
        "icon": "fa-shield-halved",
        "color": "#f47067",
    },
    "Entitlement": {"kind": "rs_Entitlement", "icon": "fa-key", "color": "#e3b341"},
    "XPC_Service": {"kind": "rs_XPCService", "icon": "fa-plug", "color": "#56d364"},
    "LaunchItem": {"kind": "rs_LaunchItem", "icon": "fa-clock", "color": "#d29922"},
    "Keychain_Item": {"kind": "rs_KeychainItem", "icon": "fa-lock", "color": "#bc8cff"},
    "MDM_Profile": {"kind": "rs_MDMProfile", "icon": "fa-building", "color": "#8b949e"},
    "User": {"kind": "rs_User", "icon": "fa-user", "color": "#c9d1d9"},
    "LocalGroup": {"kind": "rs_LocalGroup", "icon": "fa-users", "color": "#79c0ff"},
    "RemoteAccessService": {
        "kind": "rs_RemoteAccess",
        "icon": "fa-network-wired",
        "color": "#ffa657",
    },
    "FirewallPolicy": {"kind": "rs_Firewall", "icon": "fa-fire", "color": "#db6d28"},
    "LoginSession": {
        "kind": "rs_LoginSession",
        "icon": "fa-right-to-bracket",
        "color": "#7ee787",
    },
    "AuthorizationRight": {
        "kind": "rs_AuthRight",
        "icon": "fa-gavel",
        "color": "#ff7b72",
    },
    "AuthorizationPlugin": {
        "kind": "rs_AuthPlugin",
        "icon": "fa-puzzle-piece",
        "color": "#c297eb",
    },
    "SystemExtension": {
        "kind": "rs_SystemExt",
        "icon": "fa-microchip",
        "color": "#a5d6ff",
    },
    "SudoersRule": {
        "kind": "rs_SudoersRule",
        "icon": "fa-terminal",
        "color": "#ffa198",
    },
    "CriticalFile": {
        "kind": "rs_CriticalFile",
        "icon": "fa-file-shield",
        "color": "#f778ba",
    },
    "Computer": {"kind": "rs_Computer", "icon": "fa-laptop", "color": "#6cb6ff"},
    "CertificateAuthority": {
        "kind": "rs_CertAuthority",
        "icon": "fa-certificate",
        "color": "#d2a8ff",
    },
    "BluetoothDevice": {
        "kind": "rs_BluetoothDevice",
        "icon": "fa-bluetooth-b",
        "color": "#1f6feb",
    },
    "KerberosArtifact": {
        "kind": "rs_KerberosArtifact",
        "icon": "fa-ticket",
        "color": "#ea6045",
    },
    "ADGroup": {"kind": "rs_ADGroup", "icon": "fa-sitemap", "color": "#388bfd"},
    "Vulnerability": {"kind": "rs_Vulnerability", "icon": "fa-bug", "color": "#f85149"},
    "AttackTechnique": {
        "kind": "rs_AttackTechnique",
        "icon": "fa-crosshairs",
        "color": "#da3633",
    },
    "SandboxProfile": {
        "kind": "rs_SandboxProfile",
        "icon": "fa-box",
        "color": "#2ea043",
    },
    "ADUser": {"kind": "rs_ADUser", "icon": "fa-user-shield", "color": "#388bfd"},
    "ThreatGroup": {
        "kind": "rs_ThreatGroup",
        "icon": "fa-skull-crossbones",
        "color": "#b62324",
    },
    "CWE": {"kind": "rs_CWE", "icon": "fa-triangle-exclamation", "color": "#e09b13"},
    "Recommendation": {
        "kind": "rs_Recommendation",
        "icon": "fa-lightbulb",
        "color": "#3fb950",
    },
}

# ── Edge type mapping ───────────────────────────────────────────────────────

EDGE_TYPE_MAP: dict[str, dict] = {
    "HAS_TCC_GRANT": {"kind": "rs_HasTCCGrant", "traversable": True},
    "HAS_ENTITLEMENT": {"kind": "rs_HasEntitlement", "traversable": False},
    "CAN_INJECT_INTO": {"kind": "rs_CanInjectInto", "traversable": True},
    "CHILD_INHERITS_TCC": {"kind": "rs_ChildInheritsTCC", "traversable": True},
    "CAN_SEND_APPLE_EVENT": {"kind": "rs_CanSendAppleEvent", "traversable": True},
    "COMMUNICATES_WITH": {"kind": "rs_CommunicatesWith", "traversable": True},
    "PERSISTS_VIA": {"kind": "rs_PersistsVia", "traversable": True},
    "RUNS_AS": {"kind": "rs_RunsAs", "traversable": False},
    "CAN_READ_KEYCHAIN": {"kind": "rs_CanReadKeychain", "traversable": True},
    "CONFIGURES": {"kind": "rs_Configures", "traversable": False},
    "SIGNED_BY_SAME_TEAM": {"kind": "rs_SameTeam", "traversable": False},
    "MEMBER_OF": {"kind": "rs_MemberOf", "traversable": False},
    "ACCESSIBLE_BY": {"kind": "rs_AccessibleBy", "traversable": True},
    "HAS_FIREWALL_RULE": {"kind": "rs_HasFirewallRule", "traversable": False},
    "CAN_HIJACK": {"kind": "rs_CanHijack", "traversable": True},
    "HAS_TRANSITIVE_FDA": {"kind": "rs_TransitiveFDA", "traversable": True},
    "HAS_SESSION": {"kind": "rs_HasSession", "traversable": False},
    "SUDO_NOPASSWD": {"kind": "rs_SudoNopasswd", "traversable": True},
    "MDM_OVERGRANT": {"kind": "rs_MdmOvergrant", "traversable": True},
    "SHARES_KEYCHAIN_GROUP": {"kind": "rs_SharesKeychainGroup", "traversable": False},
    "CAN_WRITE": {"kind": "rs_CanWrite", "traversable": True},
    "PROTECTS": {"kind": "rs_Protects", "traversable": False},
    "CAN_MODIFY_TCC": {"kind": "rs_CanModifyTCC", "traversable": True},
    "CAN_INJECT_SHELL": {"kind": "rs_CanInjectShell", "traversable": True},
    "INSTALLED_ON": {"kind": "rs_InstalledOn", "traversable": False},
    "LOCAL_TO": {"kind": "rs_LocalTo", "traversable": False},
    "CAN_CONTROL_VIA_A11Y": {"kind": "rs_CanControlViaA11Y", "traversable": True},
    "CAN_BLIND_MONITORING": {"kind": "rs_CanBlindMonitoring", "traversable": True},
    "CAN_DEBUG": {"kind": "rs_CanDebug", "traversable": True},
    "SIGNED_BY_CA": {"kind": "rs_SignedByCA", "traversable": False},
    "ISSUED_BY": {"kind": "rs_IssuedBy", "traversable": False},
    "PAIRED_WITH": {"kind": "rs_PairedWith", "traversable": False},
    "CAN_CHANGE_PASSWORD": {"kind": "rs_CanChangePassword", "traversable": True},
    "MAPPED_TO": {"kind": "rs_MappedTo", "traversable": False},
    "AD_USER_OF": {"kind": "rs_ADUserOf", "traversable": False},
    "FOUND_ON": {"kind": "rs_FoundOn", "traversable": False},
    "HAS_KERBEROS_CACHE": {"kind": "rs_HasKerberosCache", "traversable": True},
    "HAS_KEYTAB": {"kind": "rs_HasKeytab", "traversable": False},
    "CAN_READ_KERBEROS": {"kind": "rs_CanReadKerberos", "traversable": True},
    "AFFECTED_BY": {"kind": "rs_AffectedBy", "traversable": True},
    "MAPS_TO_TECHNIQUE": {"kind": "rs_MapsToTechnique", "traversable": False},
    "HAS_SANDBOX_PROFILE": {"kind": "rs_HasSandboxProfile", "traversable": False},
    "CAN_ESCAPE_SANDBOX": {"kind": "rs_CanEscapeSandbox", "traversable": True},
    "CAN_ACCESS_MACH_SERVICE": {"kind": "rs_CanAccessMachService", "traversable": True},
    "BYPASSED_GATEKEEPER": {"kind": "rs_BypassedGatekeeper", "traversable": True},
    "SAME_IDENTITY": {"kind": "rs_SameIdentity", "traversable": True},
    "AD_MEMBER_OF": {"kind": "rs_ADMemberOf", "traversable": True},
    "USES_TECHNIQUE": {"kind": "rs_UsesTechnique", "traversable": False},
    "HAS_CWE": {"kind": "rs_HasCWE", "traversable": False},
    "HAS_RECOMMENDATION": {"kind": "rs_HasRecommendation", "traversable": False},
    "MITIGATES": {"kind": "rs_Mitigates", "traversable": False},
}


# ── Node ID generation ──────────────────────────────────────────────────────


def _sanitize(text: str) -> str:
    """Convert text to a safe ID component."""
    return "".join(c if c.isalnum() or c in "-_." else "-" for c in text)


def make_node_id(hostname: str, label: str, key: str) -> str:
    """Generate a unique OpenGraph node ID."""
    return f"rs-{_sanitize(hostname)}-{_sanitize(label.lower())}-{_sanitize(key)}"


# ── Node key extraction ─────────────────────────────────────────────────────


def _node_key(label: str, props: dict) -> str:
    """Extract the unique key for a node based on its label."""
    # Keychain_Item uses a composite key not expressible as a single property name.
    if label == "Keychain_Item":
        return f"{props.get('label', '')}-{props.get('kind', '')}"
    if label == "Application":
        return str(props.get("app_key") or props.get("bundle_id", "unknown"))
    if label == "Computer":
        return str(props.get("computer_key") or props.get("hostname", "unknown"))
    if label == "SandboxProfile":
        return str(props.get("profile_key") or props.get("bundle_id", "unknown"))
    key = NODE_KEY_PROPERTY.get(label, "name")
    return str(props.get(key, "unknown"))


# ── Node properties ─────────────────────────────────────────────────────────


def _node_display_name(label: str, props: dict) -> str:
    """Human-readable display name for a node."""
    if label == "Application":
        return props.get("name", props.get("bundle_id", "Unknown App"))
    if label == "TCC_Permission":
        return props.get("display_name", props.get("service", "Unknown Permission"))
    if label == "Entitlement":
        return props.get("name", "Unknown Entitlement")
    if label == "XPC_Service":
        return props.get("label", "Unknown XPC")
    if label == "Keychain_Item":
        return props.get("label", "Unknown Keychain Item")
    return props.get("name", props.get("display_name", props.get("label", "Unknown")))


def _serialize_props(props: dict) -> dict:
    """Convert Neo4j node properties to JSON-serializable dict."""
    result = {}
    for k, v in props.items():
        if isinstance(v, (str, int, float, bool)) or v is None:
            result[k] = v
        elif isinstance(v, list):
            result[k] = [str(item) for item in v]
        else:
            result[k] = str(v)
    return result


# ── Export functions ─────────────────────────────────────────────────────────


def export_nodes(session, hostname: str) -> list[dict]:
    """Export all graph nodes as OpenGraph node objects (single query)."""
    known_labels = list(NODE_TYPE_MAP.keys())
    result = session.run(
        """
        MATCH (n)
        WHERE any(l IN labels(n) WHERE l IN $known_labels)
        RETURN n, labels(n) AS labels
        """,
        known_labels=known_labels,
    )

    nodes = []
    for record in result:
        label = _primary_label(record["labels"])
        type_info = NODE_TYPE_MAP.get(label)
        if not type_info:
            continue

        props = dict(record["n"])
        key = _node_key(label, props)

        nodes.append(
            {
                "id": make_node_id(hostname, label, key),
                "kind": type_info["kind"],
                "label": _node_display_name(label, props),
                "properties": {
                    **_serialize_props(props),
                    "_icon": type_info["icon"],
                    "_color": type_info["color"],
                },
            }
        )

    return nodes


def export_edges(session, hostname: str) -> list[dict]:
    """Export all graph edges as OpenGraph edge objects (single query)."""
    known_types = list(EDGE_TYPE_MAP.keys())
    result = session.run(
        """
        MATCH (s)-[r]->(t)
        WHERE type(r) IN $known_types
        RETURN labels(s) AS src_labels, s AS src,
               labels(t) AS tgt_labels, t AS tgt,
               r AS rel, type(r) AS rel_type
        """,
        known_types=known_types,
    )

    edges = []
    for record in result:
        rel_type = record["rel_type"]
        type_info = EDGE_TYPE_MAP.get(rel_type)
        if not type_info:
            continue

        src_label = _primary_label(record["src_labels"])
        tgt_label = _primary_label(record["tgt_labels"])
        src_props = dict(record["src"])
        tgt_props = dict(record["tgt"])
        rel_props = dict(record["rel"])

        edges.append(
            {
                "source": make_node_id(
                    hostname, src_label, _node_key(src_label, src_props)
                ),
                "target": make_node_id(
                    hostname, tgt_label, _node_key(tgt_label, tgt_props)
                ),
                "kind": type_info["kind"],
                "properties": {
                    **_serialize_props(rel_props),
                    "_traversable": type_info["traversable"],
                },
            }
        )

    return edges


def _primary_label(labels: list[str]) -> str:
    """Pick the primary label from a node's label list (prefer our known labels)."""
    known = set(NODE_TYPE_MAP.keys())
    for label in labels:
        if label in known:
            return label
    return labels[0] if labels else "Unknown"


def export_cross_domain(session, hostname: str) -> dict:
    """
    Export cross-domain edges matching Rootstock users to AD/Azure users by name.
    Separate file without source_kind to avoid the deletion caveat.

    Emits rs_User nodes and rs_SameIdentity edges that map Rootstock users to
    BloodHound AZUser/User nodes by matching on username. The consuming
    BloodHound instance must already have the AD/Azure nodes loaded.
    """
    nodes = []
    edges = []

    result = session.run("MATCH (u:User) RETURN u")
    for record in result:
        props = dict(record["u"])
        username = props.get("name", "unknown")
        rs_id = make_node_id(hostname, "User", username)

        nodes.append(
            {
                "id": rs_id,
                "kind": "rs_User",
                "label": username,
                "properties": _serialize_props(props),
            }
        )

        # Emit a cross-domain edge stub: rs_User → AZUser (matched by name).
        # NOTE: The target ID format "az-user-{username}" is a stub that only
        # resolves if a BloodHound AZUser node with that exact ID exists in the
        # consuming graph. For cross-domain correlation to work, the BloodHound
        # import must use the same ID format or the consuming tool must perform
        # username-based matching via the match_key property.
        edges.append(
            {
                "source": rs_id,
                "target": f"az-user-{_sanitize(username)}",
                "kind": "rs_SameIdentity",
                "properties": {
                    "match_key": username,
                    "_traversable": False,
                },
            }
        )

    return {
        "metadata": {
            "type": "cross_domain",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "hostname": hostname,
        },
        "graph": {
            "nodes": nodes,
            "edges": edges,
        },
    }


def build_opengraph(session, hostname: str) -> dict:
    """Build the complete OpenGraph JSON structure."""
    nodes = export_nodes(session, hostname)
    edges = export_edges(session, hostname)

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


# ── CLI ──────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export Rootstock graph as BloodHound OpenGraph JSON"
    )
    add_neo4j_args(parser)
    parser.add_argument("--output", "-o", required=True, help="Output JSON file path")
    parser.add_argument(
        "--cross-domain",
        action="store_true",
        help="Export cross-domain edges only (no source_kind)",
    )
    parser.add_argument(
        "--hostname",
        default=None,
        help="Override hostname for node IDs (default: query from graph)",
    )
    args = parser.parse_args()

    driver = connect_from_args(args)

    with driver.session() as session:
        # Determine hostname from graph data or CLI
        hostname = args.hostname
        if not hostname:
            result = session.run(
                "MATCH (a:Application) WHERE a.scan_id IS NOT NULL "
                "RETURN a.scan_id AS scan_id LIMIT 1"
            )
            row = result.single()
            hostname = row["scan_id"][:8] if row else "rootstock"

        if args.cross_domain:
            data = export_cross_domain(session, hostname)
        else:
            data = build_opengraph(session, hostname)

    driver.close()

    output_path = Path(args.output)
    output_path.write_text(json.dumps(data, indent=2) + "\n")

    node_count = len(data["graph"]["nodes"])
    edge_count = len(data["graph"]["edges"])
    print(f"Exported {node_count} nodes, {edge_count} edges to {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
