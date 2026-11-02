"""Cross-domain OpenGraph export split from the core exporter."""

from __future__ import annotations

from datetime import datetime, timezone


def export_cross_domain(session, hostname: str) -> dict:
    """Export Rootstock users and their matching Azure identity edges."""
    from .opengraph_mapping import make_node_id, sanitize, serialize_props

    nodes: list[dict] = []
    edges: list[dict] = []
    for record in session.run("MATCH (u:User) RETURN u"):
        properties = dict(record["u"])
        username = properties.get("name", "unknown")
        rootstock_id = make_node_id(hostname, "User", username)
        nodes.append(
            {
                "id": rootstock_id,
                "kind": "rs_User",
                "label": username,
                "properties": serialize_props(properties),
            }
        )
        edges.append(
            {
                "source": rootstock_id,
                "target": f"az-user-{sanitize(username)}",
                "kind": "rs_SameIdentity",
                "properties": {"match_key": username, "_traversable": False},
            }
        )
    return {
        "metadata": {
            "type": "cross_domain",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "hostname": hostname,
        },
        "graph": {"nodes": nodes, "edges": edges},
    }
