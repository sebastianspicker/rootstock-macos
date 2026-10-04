"""HTTP route handlers for the Rootstock Graph API, collected on one APIRouter."""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from neo4j import Query
from neo4j.exceptions import DriverError, Neo4jError

from ..constants import INTERACTIVE_GRAPH_MAX_EDGES, INTERACTIVE_GRAPH_MAX_NODES
from ..inference.clear_owned import clear_all, clear_by_bundle_id, clear_by_username
from ..inference.mark_owned import (
    list_owned,
    mark_by_bundle_id,
    mark_by_label_key,
    mark_by_username,
)
from ..inference.tier_classification import classify
from ..reporting.opengraph_export import build_opengraph
from ..reporting.query_runner import discover_queries, find_query
from ..reporting.viewer import render_viewer_html
from ..cypher import first_cypher_statement, run_query
from ..server_validation import validate_adhoc_cypher as _validate_adhoc_cypher
from ..server_validation import validate_api_cypher as _validate_api_cypher
from .dependencies import (
    ADHOC_CYPHER_TIMEOUT_SECONDS,
    MAX_ADHOC_CYPHER_LENGTH,
    MAX_ADHOC_CYPHER_ROWS,
    READ_SESSION_DEPENDENCY,
    SESSION_DEPENDENCY,
    logger,
)
from .reports import ReportRequest, generate_report
from .schemas import ClearOwnedRequest, CypherRequest, MarkOwnedRequest, QueryRunRequest

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def serve_viewer(request: Request):
    """Serve the live interactive viewer without embedding graph data."""
    data = _empty_graph_payload()
    return HTMLResponse(content=render_viewer_html(data, title="Live Attack Graph", mode="live"))


@router.get("/api/queries")
def list_queries():
    """List all available Cypher queries with metadata."""
    queries = discover_queries()
    return [
        {
            "id": query["id"],
            "filename": query["filename"],
            "name": query["name"],
            "purpose": query["purpose"],
            "category": query["category"],
            "severity": query["severity"],
            "parameters": query["parameters"],
        }
        for query in queries
    ]


@router.post("/api/report")
def report_endpoint(body: ReportRequest, session=READ_SESSION_DEPENDENCY):
    """Return an in-memory assessment for the browser to download locally."""
    return generate_report(session, body)


@router.post("/api/queries/{query_id}/run")
def run_query_endpoint(
    query_id: str,
    body: QueryRunRequest | None = None,
    session=READ_SESSION_DEPENDENCY,
):
    """Execute a query by ID and return results as JSON."""
    query = find_query(discover_queries(), query_id)
    if not query:
        raise HTTPException(status_code=404, detail=f"Query '{query_id}' not found")

    cypher = first_cypher_statement(query["cypher"])
    if _validate_api_cypher(cypher):
        logger.error("Configured query %s is not read-only", query["id"])
        raise HTTPException(status_code=500, detail="Configured query is not read-only")
    params = body.params if body else {}
    try:
        rows = run_query(
            session,
            Query(cypher, timeout=ADHOC_CYPHER_TIMEOUT_SECONDS),
            params or {},
            maximum_rows=MAX_ADHOC_CYPHER_ROWS + 1,
        )
    except HTTPException:
        raise
    except (DriverError, Neo4jError) as error:
        logger.warning("Query %s failed: %s", query["id"], error)
        raise HTTPException(status_code=400, detail="Query execution failed") from error

    truncated = len(rows) > MAX_ADHOC_CYPHER_ROWS
    rows = rows[:MAX_ADHOC_CYPHER_ROWS]
    return {
        "query": {
            "id": query["id"],
            "name": query["name"],
            "category": query["category"],
            "severity": query["severity"],
        },
        "rows": rows,
        "count": len(rows),
        "truncated": truncated,
    }


@router.get("/api/graph")
def get_graph(session=READ_SESSION_DEPENDENCY):
    """Return the full OpenGraph JSON for viewer refresh."""
    _hostname, data = _build_live_graph(session)
    return data


@router.post("/api/mark-owned")
def mark_owned_endpoint(body: MarkOwnedRequest, session=SESSION_DEPENDENCY):
    """Mark nodes as owned (compromised)."""
    timestamp = datetime.now(timezone.utc).isoformat()
    with session.begin_transaction() as transaction:
        if body.bundle_ids:
            count = mark_by_bundle_id(transaction, body.bundle_ids, timestamp)
        elif body.usernames:
            count = mark_by_username(transaction, body.usernames, timestamp)
        else:
            count = mark_by_label_key(transaction, body.label, body.keys, timestamp)
    if count == 0:
        raise HTTPException(status_code=404, detail="No matching nodes found")
    return {"marked": count, "timestamp": timestamp}


@router.post("/api/clear-owned")
def clear_owned_endpoint(body: ClearOwnedRequest, session=SESSION_DEPENDENCY):
    """Clear owned markers from nodes."""
    if body.all:
        count = clear_all(session)
    elif body.bundle_ids:
        count = clear_by_bundle_id(session, body.bundle_ids)
    elif body.usernames:
        count = clear_by_username(session, body.usernames)
    else:
        raise HTTPException(status_code=400, detail="Specify 'all', 'bundle_ids', or 'usernames'")
    return {"cleared": count}


@router.get("/api/owned")
def get_owned(session=READ_SESSION_DEPENDENCY):
    """List all currently owned nodes."""
    results = []
    for item in list_owned(session):
        properties = item.get("props", {})
        results.append(
            {
                "labels": item.get("labels", []),
                "name": properties.get(
                    "name", properties.get("bundle_id", properties.get("label", "?"))
                ),
                "owned_at": properties.get("owned_at", "?"),
                "properties": properties,
            }
        )
    return {"owned": results, "count": len(results)}


@router.post("/api/tier-classify")
def tier_classify_endpoint(session=SESSION_DEPENDENCY):
    """Run tier classification on all Application nodes."""
    tier0, tier1, tier2 = classify(session)
    return {"tier0": tier0, "tier1": tier1, "tier2": tier2, "total": tier0 + tier1 + tier2}


def _limited_records(result) -> tuple[list[Any], bool]:
    records = []
    truncated = False
    for index, record in enumerate(result):
        if index >= MAX_ADHOC_CYPHER_ROWS:
            truncated = True
            break
        records.append(record)
    return records, truncated


@router.post("/api/cypher")
def run_cypher_endpoint(body: CypherRequest, session=READ_SESSION_DEPENDENCY):
    """Execute a bounded, read-only ad-hoc Cypher query."""
    if len(body.cypher) > MAX_ADHOC_CYPHER_LENGTH:
        raise HTTPException(status_code=413, detail="Cypher query exceeds 10000 characters")
    error = _validate_adhoc_cypher(body.cypher)
    if error:
        raise HTTPException(status_code=403, detail=error)
    try:
        result = session.run(
            Query(body.cypher, timeout=ADHOC_CYPHER_TIMEOUT_SECONDS), body.params or {}
        )
        records, truncated = _limited_records(result)
        columns = list(records[0].keys()) if records else []
        rows = [dict(record) for record in records]
    except HTTPException:
        raise
    except (DriverError, Neo4jError) as error:
        logger.warning("Ad-hoc Cypher failed: %s", error)
        raise HTTPException(status_code=400, detail="Query execution failed") from error
    return {"columns": columns, "rows": rows, "count": len(rows), "truncated": truncated}


def _get_hostname(session) -> str:
    result = session.run(
        Query("MATCH (c:Computer) RETURN c.hostname AS hostname LIMIT 1", timeout=5.0)
    )
    row = result.single()
    if row and row["hostname"]:
        return row["hostname"]
    result = session.run(
        Query(
            "MATCH (a:Application) WHERE a.scan_id IS NOT NULL RETURN a.scan_id AS scan_id LIMIT 1",
            timeout=5.0,
        )
    )
    row = result.single()
    if row and row["scan_id"]:
        return row["scan_id"][:8]
    return "rootstock"


def _build_live_graph(session) -> tuple[str, dict[str, Any]]:
    """Build the live graph payload with deterministic fallback coordinates."""
    try:
        hostname = _get_hostname(session)
        data = build_opengraph(
            session,
            hostname,
            maximum_nodes=INTERACTIVE_GRAPH_MAX_NODES + 1,
            maximum_edges=INTERACTIVE_GRAPH_MAX_EDGES + 1,
        )
    except (DriverError, Neo4jError) as error:
        raise HTTPException(status_code=503, detail="Graph retrieval failed") from error
    graph = data.get("graph", {})
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    if len(nodes) > INTERACTIVE_GRAPH_MAX_NODES or len(edges) > INTERACTIVE_GRAPH_MAX_EDGES:
        raise HTTPException(
            status_code=413,
            detail=(
                "Live graph exceeds the interactive limit of "
                f"{INTERACTIVE_GRAPH_MAX_NODES} nodes and "
                f"{INTERACTIVE_GRAPH_MAX_EDGES} edges"
            ),
        )
    for index, node in enumerate(nodes):
        if isinstance(node.get("x"), int | float) and isinstance(node.get("y"), int | float):
            continue
        angle = index * 2.399963229728653
        radius = 40 + math.sqrt(index + 1) * 35
        node["x"] = round(1000 + math.cos(angle) * radius, 1)
        node["y"] = round(1000 + math.sin(angle) * radius, 1)
    return hostname, data


def _empty_graph_payload() -> dict[str, Any]:
    return {
        "metadata": {
            "hostname": "rootstock",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "graph": {"nodes": [], "edges": []},
    }
