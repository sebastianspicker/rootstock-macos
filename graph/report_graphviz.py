"""
report_graphviz.py — Graphviz DOT format export for Rootstock graphs.

CLI: python3 report_graphviz.py --neo4j bolt://localhost:7687 --output graph.dot

Color coding (security dashboard palette for dark backgrounds):
  Application    = #4a90d9  (steel blue — primary entities)
  TCC_Permission = #e05252  (red — security-critical grants)
  Entitlement    = #d4a843  (amber — capability markers)
  XPC_Service    = #4caf7c  (green — service endpoints)
  LaunchItem     = #d28f22  (orange — persistence mechanisms)
  MDM_Profile    = #9c7ec2  (purple — management controls)
  User           = #b0bec5  (grey — identity)
  Keychain_Item  = #ab7fcc  (violet — credential stores)
  Vulnerability  = #e04545  (bright red — threats)
  Computer       = #5a9fd4  (blue — infrastructure)

Edge styles:
  solid  = explicit relationships (imported directly from scan data)
  dashed = inferred relationships (CAN_INJECT_INTO, CHILD_INHERITS_TCC, etc.)
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from neo4j import GraphDatabase

from utils import sanitize_id, truncate


# ── Color / Style Tables ──────────────────────────────────────────────────────

NODE_COLORS: dict[str, str] = {
    "Application": "#4a90d9",
    "TCC_Permission": "#e05252",
    "Entitlement": "#d4a843",
    "XPC_Service": "#4caf7c",
    "LaunchItem": "#d28f22",
    "MDM_Profile": "#9c7ec2",
    "User": "#b0bec5",
    "Keychain_Item": "#ab7fcc",
    "LocalGroup": "#6ca3d9",
    "RemoteAccessService": "#e08850",
    "FirewallPolicy": "#c75b28",
    "AuthorizationRight": "#e06b5e",
    "SudoersRule": "#e07a6a",
    "CriticalFile": "#e06090",
    "Computer": "#5a9fd4",
    "Vulnerability": "#e04545",
    "AttackTechnique": "#c92e2e",
    "ThreatGroup": "#9e1e1e",
    "SandboxProfile": "#2e8b4a",
    "CWE": "#c98f13",
    "Recommendation": "#3aad50",
}

# Shape mapping: node type -> Graphviz shape
# Distinct shapes aid rapid identification by security professionals.
NODE_SHAPES: dict[str, str] = {
    "Application": "box",
    "TCC_Permission": "hexagon",
    "Entitlement": "hexagon",
    "XPC_Service": "component",
    "LaunchItem": "parallelogram",
    "MDM_Profile": "folder",
    "User": "triangle",
    "Keychain_Item": "house",
    "LocalGroup": "invtriangle",
    "RemoteAccessService": "octagon",
    "FirewallPolicy": "doubleoctagon",
    "AuthorizationRight": "diamond",
    "SudoersRule": "trapezium",
    "CriticalFile": "note",
    "Computer": "box3d",
    "Vulnerability": "diamond",
    "AttackTechnique": "diamond",
    "ThreatGroup": "Mdiamond",
    "SandboxProfile": "tab",
    "CWE": "pentagon",
    "Recommendation": "cds",
}

# Relationships inferred at import time (always rendered dashed)
INFERRED_RELS = {
    "CAN_INJECT_INTO", "CHILD_INHERITS_TCC", "CAN_SEND_APPLE_EVENT",
    "HAS_TRANSITIVE_FDA", "MDM_OVERGRANT", "SHARES_KEYCHAIN_GROUP",
    "CAN_WRITE", "PROTECTS", "CAN_MODIFY_TCC", "CAN_INJECT_SHELL",
    "CAN_CONTROL_VIA_A11Y", "CAN_BLIND_MONITORING", "CAN_DEBUG",
    "CAN_CHANGE_PASSWORD",
    "CAN_READ_KERBEROS",
}

MAX_LABEL_LEN = 35


def escape_dot_string(value: object) -> str:
    """Escape a value for a quoted DOT string attribute."""
    text = str(value)
    return (
        text.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


# ── Neo4j Fetch ───────────────────────────────────────────────────────────────

DEFAULT_NODE_LIMIT = 500
DEFAULT_EDGE_LIMIT = 2000


def fetch_graph_data(
    driver,
    node_limit: int = DEFAULT_NODE_LIMIT,
    edge_limit: int = DEFAULT_EDGE_LIMIT,
) -> tuple[list[dict], list[dict]]:
    """
    Fetch nodes and relationships from Neo4j.

    Returns:
        (nodes, edges) — each a list of property dicts.
    """
    label_filter = " OR ".join(f"n:{label}" for label in NODE_COLORS)
    edge_label_a = " OR ".join(f"a:{label}" for label in NODE_COLORS)
    edge_label_b = " OR ".join(f"b:{label}" for label in NODE_COLORS)

    with driver.session() as session:
        node_result = session.run(f"""
            MATCH (n)
            WHERE {label_filter}
            RETURN elementId(n) AS id,
                   labels(n)[0]  AS label,
                   coalesce(n.name, n.display_name, n.label, n.identifier, '?') AS display,
                   n.bundle_id   AS bundle_id
            LIMIT $limit
        """, {"limit": node_limit})
        nodes = [dict(r) for r in node_result]

        edge_result = session.run(f"""
            MATCH (a)-[r]->(b)
            WHERE ({edge_label_a})
              AND ({edge_label_b})
            RETURN elementId(a) AS src_id,
                   elementId(b) AS dst_id,
                   type(r) AS rel_type,
                   coalesce(r.inferred, false) AS inferred
            LIMIT $limit
        """, {"limit": edge_limit})
        edges = [dict(r) for r in edge_result]

    if len(nodes) == node_limit:
        print(f"Warning: node limit reached ({node_limit}). Graph may be truncated. "
              f"Use --node-limit to increase.", file=sys.stderr)
    if len(edges) == edge_limit:
        print(f"Warning: edge limit reached ({edge_limit}). Graph may be truncated. "
              f"Use --edge-limit to increase.", file=sys.stderr)

    return nodes, edges


# ── DOT Generation ────────────────────────────────────────────────────────────

def generate_dot(nodes: list[dict], edges: list[dict]) -> str:
    """
    Generate a Graphviz DOT string from node and edge lists.

    Args:
        nodes: list of dicts with keys: id, label (node type), display, bundle_id
        edges: list of dicts with keys: src_id, dst_id, rel_type, inferred

    Returns:
        DOT format string.
    """
    lines = [
        "digraph rootstock {",
        '  graph [rankdir=LR fontname="Helvetica Neue" bgcolor="#0d1117" pad=0.5]',
        '  node  [fontname="Helvetica Neue" fontsize=10 style="filled,rounded"'
        ' fontcolor="#e6edf3" penwidth=1.5 color="#30363d"]',
        '  edge  [fontname="Helvetica Neue" fontsize=8 fontcolor="#8b949e"'
        ' color="#58a6ff"]',
        "",
    ]

    # elementId → dot identifier mapping
    id_map: dict[str, str] = {}
    seen_dot_ids: set[str] = set()

    for node in nodes:
        _append_dot_node(lines, id_map, seen_dot_ids, node)

    lines.append("")

    for edge in edges:
        _append_dot_edge(lines, id_map, edge)

    lines.append("}")
    return "\n".join(lines)


def _append_dot_node(
    lines: list[str],
    id_map: dict[str, str],
    seen_dot_ids: set[str],
    node: dict,
) -> None:
    raw_id = str(node["id"])
    display = node.get("display") or "?"
    node_type = node.get("label") or "Unknown"
    bundle = node.get("bundle_id") or ""
    dot_id = _unique_dot_id(bundle if bundle else display, seen_dot_ids)
    id_map[raw_id] = dot_id

    color = NODE_COLORS.get(node_type, "#444c56")
    label = escape_dot_string(truncate(display, MAX_LABEL_LEN))
    shape = NODE_SHAPES.get(node_type, "ellipse")
    lines.append(f'  {dot_id} [label="{label}" fillcolor="{color}" shape={shape}]')


def _unique_dot_id(value: object, seen_dot_ids: set[str]) -> str:
    base_id = sanitize_id(value)
    dot_id = base_id
    counter = 0
    while dot_id in seen_dot_ids:
        counter += 1
        dot_id = f"{base_id}_{counter}"
    seen_dot_ids.add(dot_id)
    return dot_id


def _append_dot_edge(lines: list[str], id_map: dict[str, str], edge: dict) -> None:
    rel = edge.get("rel_type", "REL")
    src_dot = id_map.get(str(edge["src_id"]))
    dst_dot = id_map.get(str(edge["dst_id"]))
    if src_dot is None or dst_dot is None:
        return

    is_inferred = edge.get("inferred", False) or rel in INFERRED_RELS
    style = "dashed" if is_inferred else "solid"
    edge_color = _edge_color(rel, is_inferred=is_inferred)
    safe_rel = escape_dot_string(rel)
    lines.append(
        f'  {src_dot} -> {dst_dot} [label="{safe_rel}" style={style}'
        f' color="{edge_color}" fontcolor="{edge_color}"]'
    )


def _edge_color(rel: str, *, is_inferred: bool) -> str:
    high_risk_rels = {"CAN_INJECT_INTO", "CAN_MODIFY_TCC", "CAN_ESCAPE_SANDBOX"}
    if rel in high_risk_rels:
        return "#f85149"
    if is_inferred:
        return "#d29922"
    return "#58a6ff"



# ── CLI ───────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export Rootstock graph to Graphviz DOT format"
    )
    parser.add_argument("--neo4j", default="bolt://localhost:7687", help="Neo4j bolt URI")
    parser.add_argument("--username", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", default=None, help="Neo4j password (or set NEO4J_PASSWORD)")
    parser.add_argument("--output", required=True, help="Output .dot file path")
    parser.add_argument(
        "--node-limit", type=int, default=DEFAULT_NODE_LIMIT,
        help=f"Max nodes to fetch (default: {DEFAULT_NODE_LIMIT})",
    )
    parser.add_argument(
        "--edge-limit", type=int, default=DEFAULT_EDGE_LIMIT,
        help=f"Max edges to fetch (default: {DEFAULT_EDGE_LIMIT})",
    )
    return parser.parse_args()


def _connect_driver(args: argparse.Namespace):
    password = args.password or os.environ.get("NEO4J_PASSWORD")
    if not password:
        print("ERROR: Neo4j password required via --password or NEO4J_PASSWORD env var",
              file=sys.stderr)
        return None

    driver = GraphDatabase.driver(args.neo4j, auth=(args.username, password))
    try:
        driver.verify_connectivity()
    except Exception as e:
        print(f"Cannot connect to Neo4j at {args.neo4j}: {e}", file=sys.stderr)
        return None
    return driver


def _write_graphviz_output(args: argparse.Namespace, nodes: list[dict], edges: list[dict]) -> None:
    print(f"  {len(nodes)} nodes, {len(edges)} edges", file=sys.stderr)
    dot_content = generate_dot(nodes, edges)
    out_path = Path(args.output)
    out_path.write_text(dot_content, encoding="utf-8")
    print(f"DOT file written to {out_path}", file=sys.stderr)


def main() -> int:
    args = _parse_args()
    driver = _connect_driver(args)
    if driver is None:
        return 1
    print(f"Fetching graph data from {args.neo4j}…", file=sys.stderr)
    nodes, edges = fetch_graph_data(driver, args.node_limit, args.edge_limit)
    driver.close()
    _write_graphviz_output(args, nodes, edges)
    return 0


if __name__ == "__main__":
    sys.exit(main())
