"""
report_diagrams.py — Mermaid diagram generation for Rootstock security reports.

All functions are pure (no Neo4j dependency) — they take query result dicts
and return formatted diagram strings suitable for embedding in Markdown.
"""

from __future__ import annotations

from utils import sanitize_id as sanitize_mermaid_id, truncate as _truncate


# ── TCC Node Detection ────────────────────────────────────────────────────────

_TCC_KEYWORDS = {
    "full disk access", "accessibility", "screen recording",
    "microphone", "camera", "location", "contacts", "calendar",
    "reminders", "photos", "bluetooth", "homekit", "health",
    "appleevents", "developer tools",
}


def _is_tcc_node(name: str) -> bool:
    """Heuristic: is this node a TCC permission node?"""
    lower = name.lower()
    return any(kw in lower for kw in _TCC_KEYWORDS) or name.startswith("kTCC")


# ── Mermaid Attack Path Flowchart ─────────────────────────────────────────────

def mermaid_attack_path(path_result: dict) -> str:
    """
    Generate a Mermaid LR flowchart for a single attack path.

    Args:
        path_result: dict with keys:
            - node_names: list[str] — display names of nodes in path
            - rel_types:  list[str] — relationship types between nodes
            - path_length: int

    Returns:
        Mermaid flowchart string (fenced code block), or "" if path is empty.
    """
    nodes: list[str] = path_result.get("node_names") or []
    rels: list[str] = path_result.get("rel_types") or []

    if not nodes or len(nodes) < 2:
        return ""

    # Ensure nodes and rels are consistent lengths
    edge_count = min(len(nodes) - 1, len(rels))
    nodes = nodes[: edge_count + 1]
    rels = rels[:edge_count]

    lines = ["```mermaid", "graph LR"]

    # Unique node IDs: sanitize name + index suffix to avoid collisions
    ids = [sanitize_mermaid_id(n) + str(i) for i, n in enumerate(nodes)]

    for name, node_id in zip(nodes, ids):
        label = _truncate(name).replace('"', "'")
        lines.append(f'  {node_id}["{label}"]')

    for i in range(edge_count):
        src = ids[i]
        dst = ids[i + 1]
        rel = rels[i]
        lines.append(f"  {src} -->|{rel}| {dst}")

    # Style: TCC permission nodes red, attacker node orange
    for name, node_id in zip(nodes, ids):
        if _is_tcc_node(name):
            lines.append(f"  style {node_id} fill:#ff6666,color:#fff")
        elif "attacker" in name.lower():
            lines.append(f"  style {node_id} fill:#ff9933,color:#fff")

    lines.append("```")
    return "\n".join(lines)


def mermaid_attack_paths_block(path_rows: list[dict], max_paths: int = 3) -> str:
    """
    Generate Mermaid diagrams for the top N attack paths.
    Falls back to text representation when diagram generation fails.
    """
    if not path_rows:
        return "_No attack paths found._"

    parts = []
    for i, row in enumerate(path_rows[:max_paths]):
        hops = row.get("path_length", "?")
        parts.append(f"**Path {i + 1}** ({hops} hop{'s' if hops != 1 else ''})")
        diagram = mermaid_attack_path(row)
        if diagram:
            parts.append(diagram)
        else:
            # Text fallback for paths that can't be diagrammed
            names = row.get("node_names") or []
            rel_types = row.get("rel_types") or []
            steps: list[str] = []
            for j, name in enumerate(names):
                steps.append(f"`{name}`")
                if j < len(rel_types):
                    steps.append(f"→ _{rel_types[j]}_ →")
            parts.append(" ".join(steps))
        parts.append("")

    return "\n".join(parts)


# ── Mermaid Pie Chart ─────────────────────────────────────────────────────────

def mermaid_tcc_pie(rows: list[dict], top_n: int = 10) -> str:
    """
    Generate a Mermaid pie chart of TCC grant distribution.

    Args:
        rows: list of dicts with keys 'permission' (str) and 'total_grants' (int)
        top_n: include only the top N permissions by grant count

    Returns:
        Mermaid pie chart string (fenced code block), or a "no data" message.
    """
    if not rows:
        return "_No TCC grant data available._"

    sorted_rows = sorted(rows, key=lambda r: r.get("total_grants", 0), reverse=True)
    top = sorted_rows[:top_n]

    lines = ["```mermaid", "pie title TCC Permission Distribution"]
    for row in top:
        label = row.get("permission", "Unknown")
        count = row.get("total_grants", 0)
        safe_label = label.replace('"', "'")
        lines.append(f'  "{safe_label}" : {count}')
    lines.append("```")
    return "\n".join(lines)


# ── Tier Classification Pie Chart ─────────────────────────────────────────────

def mermaid_tier_pie(tier_counts: dict[str, int]) -> str:
    """
    Generate a Mermaid pie chart of Tier 0 / Tier 1 / Tier 2 / Unclassified counts.

    Args:
        tier_counts: pre-aggregated counts keyed by tier label (e.g. {"Tier 0": 5, ...}).

    Returns:
        Mermaid pie chart string (fenced code block).
    """
    if not tier_counts:
        return "_No tier classification data available._"

    # Sort tiers in a natural order
    tier_order = ["Tier 0", "Tier 1", "Tier 2", "Unclassified"]
    sorted_tiers = sorted(tier_counts.keys(), key=lambda t: tier_order.index(t) if t in tier_order else 99)

    lines = ["```mermaid", "pie title Application Tier Classification"]
    for tier in sorted_tiers:
        safe_label = tier.replace('"', "'")
        lines.append(f'  "{safe_label}" : {tier_counts[tier]}')
    lines.append("```")
    return "\n".join(lines)


# ── Physical Security Posture Summary ─────────────────────────────────────────

def mermaid_posture_summary(posture_rows: list[dict]) -> str:
    """
    Generate a Mermaid graph showing physical security posture per host.

    Args:
        posture_rows: query 67 results — each row has host posture properties.

    Returns:
        Mermaid graph string (fenced code block).
    """
    if not posture_rows:
        return "_No physical security posture data available._"

    row = posture_rows[0]  # First host
    hostname = str(row.get("hostname", row.get("computer", "Host")))
    host_id = sanitize_mermaid_id(hostname)

    checks = [
        ("lockdown_mode", "Lockdown Mode", row.get("lockdown_mode")),
        ("screen_lock", "Screen Lock", row.get("screen_lock")),
        ("filevault", "FileVault", row.get("filevault")),
        ("sip", "SIP", row.get("sip")),
        ("bt_discoverable", "BT Discoverable", row.get("bluetooth_discoverable")),
        ("secure_boot", "Secure Boot", row.get("secure_boot")),
        ("external_boot", "External Boot", row.get("external_boot")),
        ("thunderbolt", "Thunderbolt Security", row.get("thunderbolt_security")),
    ]

    lines = ["```mermaid", "graph TD"]
    safe_hostname = _truncate(hostname, 25).replace('"', "'")
    lines.append(f'  {host_id}["{safe_hostname}"]')

    for check_id, label, value in checks:
        node_id = f"{host_id}_{check_id}"
        if isinstance(value, bool):
            display = "Enabled" if value else "Disabled"
            lines.append(f'  {node_id}["{label}: {display}"]')
            lines.append(f"  {host_id} --> {node_id}")
            if check_id in ("bt_discoverable", "external_boot"):
                # Discoverable / external boot allowed = bad
                colour = "#ff6666" if value else "#66bb6a"
            else:
                colour = "#66bb6a" if value else "#ff6666"
            lines.append(f"  style {node_id} fill:{colour},color:#fff")
        elif value is not None:
            safe_value = str(value).replace('"', "'")
            lines.append(f'  {node_id}["{label}: {safe_value}"]')
            lines.append(f"  {host_id} --> {node_id}")
            if check_id in ("thunderbolt", "secure_boot"):
                colour = "#66bb6a" if str(value).lower() == "full" else "#ff9933"
            else:
                colour = "#42a5f5"
            lines.append(f"  style {node_id} fill:{colour},color:#fff")

    lines.append("```")
    return "\n".join(lines)


# ── iCloud Risk Flow Diagram ─────────────────────────────────────────────────

def mermaid_icloud_risk_flow(icloud_rows: list[dict]) -> str:
    """
    Generate a Mermaid LR flowchart showing injectable app → iCloud entitlement → synced data.

    Args:
        icloud_rows: query 68 results — top injectable apps with iCloud entitlements.

    Returns:
        Mermaid flowchart string (fenced code block).
    """
    if not icloud_rows:
        return "_No iCloud risk data available._"

    lines = ["```mermaid", "graph LR"]
    lines.append('  attacker["Attacker Code"]')
    lines.append("  style attacker fill:#ff9933,color:#fff")

    seen_apps: set[str] = set()
    emitted: list[str] = []  # track ent_ids for the sync edges

    for row in icloud_rows:
        app_name = str(row.get("app_name", row.get("name", "?")))
        if app_name in seen_apps:
            continue
        seen_apps.add(app_name)
        if len(seen_apps) > 3:
            break

        idx = len(emitted)
        app_id = sanitize_mermaid_id(app_name) + str(idx)
        ent_label = str(row.get("icloud_entitlement", row.get("entitlement", "iCloud Container")))
        ent_id = f"ent_{idx}"
        emitted.append(ent_id)

        lines.append(f'  {app_id}["{_truncate(app_name)}"]')
        lines.append(f"  style {app_id} fill:#ff6666,color:#fff")
        lines.append(f'  {ent_id}["{_truncate(ent_label)}"]')
        lines.append(f"  style {ent_id} fill:#42a5f5,color:#fff")

        lines.append(f"  attacker -->|CAN_INJECT_INTO| {app_id}")
        lines.append(f"  {app_id} -->|HAS_ENTITLEMENT| {ent_id}")

    lines.append('  icloud_sync["iCloud Sync (All Devices)"]')
    lines.append("  style icloud_sync fill:#7e57c2,color:#fff")
    for ent_id in emitted:
        lines.append(f"  {ent_id} -->|syncs to| icloud_sync")

    lines.append("```")
    return "\n".join(lines)
