"""Family and cross-domain OpenGraph exports split from the core exporter."""

from __future__ import annotations

from datetime import datetime, timezone


def family_export_to_opengraph(export) -> dict:
    """Convert a validated FamilyExport into an OpenGraph/viewer payload."""
    from import_family_export import build_edge_records, build_node_records
    from opengraph_export import map_edge_for_opengraph, map_node_for_opengraph

    hostname = export.scope_name or export.source
    nodes, records_by_id = _family_nodes(
        build_node_records(export), hostname, map_node_for_opengraph
    )
    edges = _family_edges(
        build_edge_records(export),
        records_by_id,
        hostname,
        export.source,
        map_edge_for_opengraph,
    )
    return _family_payload(export, hostname, nodes, edges)


def _family_nodes(
    groups: dict, hostname: str, map_node
) -> tuple[list[dict], dict[str, tuple[str, dict]]]:
    nodes: list[dict] = []
    records_by_id: dict[str, tuple[str, dict]] = {}
    for label, records in groups.items():
        for record in records:
            properties = dict(record["props"])
            records_by_id[str(record["id"])] = (label, properties)
            mapped = map_node(hostname, label, properties)
            if mapped is not None:
                nodes.append(mapped)
    return nodes, records_by_id


def _family_edges(
    groups: dict,
    records_by_id: dict[str, tuple[str, dict]],
    hostname: str,
    source: str,
    map_edge,
) -> list[dict]:
    edges: list[dict] = []
    for relationship_type, records in groups.items():
        for record in records:
            endpoints = _family_edge_endpoints(record, records_by_id)
            if endpoints is None:
                continue
            source_node, target_node = endpoints
            mapped = map_edge(
                hostname,
                src_label=source_node[0],
                src_props=source_node[1],
                tgt_label=target_node[0],
                tgt_props=target_node[1],
                rel_type=relationship_type,
                rel_props={"source": source, "family_export": True},
            )
            if mapped is not None:
                edges.append(mapped)
    return edges


def _family_edge_endpoints(
    record: dict, records_by_id: dict[str, tuple[str, dict]]
) -> tuple[tuple[str, dict], tuple[str, dict]] | None:
    source = records_by_id.get(record["source_id"])
    target = records_by_id.get(record["target_id"])
    return (source, target) if source is not None and target is not None else None


def _family_payload(
    export, hostname: str, nodes: list[dict], edges: list[dict]
) -> dict:
    return {
        "metadata": {
            "source_kind": "RootstockFamily",
            "family_source": export.source,
            "scope_name": export.scope_name,
            "hostname": hostname,
            "node_count": len(nodes),
            "edge_count": len(edges),
        },
        "graph": {"nodes": nodes, "edges": edges},
    }


def export_cross_domain(session, hostname: str) -> dict:
    """Export Rootstock users and their matching Azure identity edges."""
    from opengraph_export import _sanitize, _serialize_props, make_node_id

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
                "properties": _serialize_props(properties),
            }
        )
        edges.append(
            {
                "source": rootstock_id,
                "target": f"az-user-{_sanitize(username)}",
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
