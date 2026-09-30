#!/usr/bin/env python3
"""
rootstock-graph-opengraph-export - Export Rootstock graph data as BloodHound OpenGraph JSON.

Queries Neo4j and produces a JSON file compatible with BloodHound CE v8+
OpenGraph ingest format. Upload via: Administration > File Ingest > Upload.

Usage:
    rootstock-graph-opengraph-export --neo4j bolt://localhost:7687 --output rootstock-opengraph.json
    rootstock-graph-opengraph-export --neo4j bolt://localhost:7687 --output cross.json --cross-domain
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from neo4j import Query

from ..constants import NODE_KEY_PROPERTY

from .opengraph_mapping import (
    EDGE_TYPE_MAP,
    NODE_TYPE_MAP,
    map_edge_for_opengraph,
    map_node_for_opengraph,
    primary_label,
)
from ..neo4j import add_neo4j_args, connect_from_args


# ── Export functions ─────────────────────────────────────────────────────────


INTERACTIVE_EXPORT_TIMEOUT = 5.0
IDENTITY_PROPERTIES = sorted(
    set(NODE_KEY_PROPERTY.values())
    | {"name", "label", "kind", "app_key", "computer_key", "profile_key", "bundle_id", "hostname"}
)


def _export_query(session, text, maximum_records, **parameters):
    if maximum_records is not None:
        text += " LIMIT $maximum_records"
        parameters["maximum_records"] = maximum_records
        return session.run(Query(text, timeout=INTERACTIVE_EXPORT_TIMEOUT), **parameters)
    return session.run(text, **parameters)


def _endpoint_properties(value):
    # Key/value pairs preserve absent keys, unlike literal Cypher map projections.
    return dict(value)


def export_nodes(
    session,
    hostname: str,
    maximum_records: int | None = None,
) -> list[dict]:
    """Export all graph nodes as OpenGraph node objects (single query)."""
    known_labels = list(NODE_TYPE_MAP.keys())
    result = _export_query(
        session,
        """
        MATCH (n)
        WHERE any(l IN labels(n) WHERE l IN $known_labels)
        RETURN n, labels(n) AS labels
        """,
        maximum_records,
        known_labels=known_labels,
    )

    nodes = []
    for record in result:
        if maximum_records is not None and len(nodes) >= maximum_records:
            break
        label = primary_label(record["labels"])
        props = dict(record["n"])
        mapped = map_node_for_opengraph(hostname, label, props)
        if mapped is not None:
            nodes.append(mapped)

    return nodes


def export_edges(
    session,
    hostname: str,
    maximum_records: int | None = None,
) -> list[dict]:
    """Export all graph edges as OpenGraph edge objects (single query)."""
    known_types = list(EDGE_TYPE_MAP.keys())
    result = _export_query(
        session,
        """
        MATCH (s)-[r]->(t)
        WHERE type(r) IN $known_types
        RETURN labels(s) AS src_labels,
               [k IN keys(s) WHERE k IN $identity_properties | [k, s[k]]] AS src,
               labels(t) AS tgt_labels,
               [k IN keys(t) WHERE k IN $identity_properties | [k, t[k]]] AS tgt,
               r AS rel, type(r) AS rel_type
        """,
        maximum_records,
        known_types=known_types,
        identity_properties=IDENTITY_PROPERTIES,
    )

    edges = []
    for record in result:
        if maximum_records is not None and len(edges) >= maximum_records:
            break
        rel_type = record["rel_type"]
        src_label = primary_label(record["src_labels"])
        tgt_label = primary_label(record["tgt_labels"])
        src_props = _endpoint_properties(record["src"])
        tgt_props = _endpoint_properties(record["tgt"])
        rel_props = dict(record["rel"])
        mapped = map_edge_for_opengraph(
            hostname,
            src_label=src_label,
            src_props=src_props,
            tgt_label=tgt_label,
            tgt_props=tgt_props,
            rel_type=rel_type,
            rel_props=rel_props,
        )
        if mapped is not None:
            edges.append(mapped)

    return edges


def export_cross_domain(session, hostname: str) -> dict:
    """
    Export cross-domain edges matching Rootstock users to AD/Azure users by name.
    Separate file without source_kind to avoid the deletion caveat.

    Emits rs_User nodes and rs_SameIdentity edges that map Rootstock users to
    BloodHound AZUser/User nodes by matching on username. The consuming
    BloodHound instance must already have the AD/Azure nodes loaded.
    """
    from .opengraph_family import export_cross_domain as build_cross_domain_opengraph

    return build_cross_domain_opengraph(session, hostname)


def build_opengraph(
    session,
    hostname: str,
    *,
    maximum_nodes: int | None = None,
    maximum_edges: int | None = None,
) -> dict:
    """Build the complete OpenGraph JSON structure."""
    nodes = export_nodes(session, hostname, maximum_nodes)
    # Interactive callers request one sentinel beyond their accepted node count.
    edges = (
        []
        if maximum_nodes is not None and len(nodes) >= maximum_nodes
        else export_edges(session, hostname, maximum_edges)
    )

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
