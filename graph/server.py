#!/usr/bin/env python3
"""
server.py - Rootstock REST API server.

Thin HTTP wrapper over existing Rootstock functions: query execution,
owned-node marking, tier classification, and live graph data for the viewer.

Usage:
    python3 graph/server.py --port 8000
    python3 graph/server.py --port 8000 --neo4j bolt://localhost:7687

Opens at http://localhost:8000/ (viewer).

Exit code 0 on success, 1 on failure.
"""

from __future__ import annotations

import argparse
import hmac
import ipaddress
import logging
import math
import os
import re
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any
from urllib.parse import SplitResult, urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from neo4j import GraphDatabase, Query, READ_ACCESS
from neo4j.exceptions import AuthError, DriverError, Neo4jError, ServiceUnavailable

# ── Imports from existing Rootstock modules ─────────────────────────────────


from query_runner import discover_queries, find_query
from utils import (
    cypher_code_only,
    first_cypher_statement,
    run_query,
    validate_read_only_cypher,
)

from opengraph_export import build_opengraph
from constants import INTERACTIVE_GRAPH_MAX_EDGES, INTERACTIVE_GRAPH_MAX_NODES
from mark_owned import (
    mark_by_bundle_id,
    mark_by_username,
    mark_by_label_key,
    list_owned,
)
from clear_owned import clear_all, clear_by_bundle_id, clear_by_username
from tier_classification import classify
from viewer import render_viewer_html


# ── Request/Response models ─────────────────────────────────────────────────


class MarkOwnedRequest(BaseModel):
    bundle_ids: list[str] | None = None
    usernames: list[str] | None = None
    label: str | None = None
    keys: list[str] | None = None


class ClearOwnedRequest(BaseModel):
    all: bool = False
    bundle_ids: list[str] | None = None
    usernames: list[str] | None = None


class QueryRunRequest(BaseModel):
    params: dict[str, Any] | None = None


class CypherRequest(BaseModel):
    cypher: str
    params: dict[str, Any] | None = None


# ── App lifecycle ───────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create Neo4j driver on startup, close on shutdown."""
    uri = app.state.neo4j_uri
    user = app.state.neo4j_user
    password = app.state.neo4j_password

    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))
        driver.verify_connectivity()
    except ServiceUnavailable:
        print("ERROR: Cannot connect to Neo4j.", file=sys.stderr)
        sys.exit(1)
    except AuthError:
        print("ERROR: Neo4j authentication failed.", file=sys.stderr)
        sys.exit(1)

    app.state.driver = driver
    print("Connected to Neo4j.")
    yield
    driver.close()
    print("Neo4j connection closed.")


app = FastAPI(
    title="Rootstock API",
    description="REST API for Rootstock macOS attack graph",
    version="0.1.0-alpha.1",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


# ── Dependencies ────────────────────────────────────────────────────────────

logger = logging.getLogger("rootstock.api")
MAX_ADHOC_CYPHER_LENGTH = 10_000
MAX_ADHOC_CYPHER_ROWS = 1_000
ADHOC_CYPHER_TIMEOUT_SECONDS = 5.0
MIN_API_TOKEN_BYTES = 32
_CALL_RE = re.compile(r"\bCALL\b", re.IGNORECASE)


def get_session(request: Request):
    """Yield a Neo4j session from the app-level driver."""
    with request.app.state.driver.session() as session:
        yield session


def get_read_session(request: Request):
    """Request Neo4j read routing; database privileges remain authoritative."""
    with request.app.state.driver.session(default_access_mode=READ_ACCESS) as session:
        yield session


SESSION_DEPENDENCY = Depends(get_session)
READ_SESSION_DEPENDENCY = Depends(get_read_session)


@app.middleware("http")
async def require_api_token(request: Request, call_next):
    """Protect all /api routes with a bearer token."""
    if request.url.path.startswith("/api/"):
        token = getattr(request.app.state, "api_token", None)
        auth_header = request.headers.get("Authorization", "")
        if not _matches_api_token(auth_header, token):
            response = JSONResponse(
                status_code=401,
                content={"detail": "Missing or invalid bearer token"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        else:
            response = await call_next(request)
    else:
        response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'unsafe-inline'; "
        "style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


def _matches_api_token(auth_header: str, token: str | None) -> bool:
    scheme, separator, presented = auth_header.partition(" ")
    return (
        bool(token)
        and separator == " "
        and scheme == "Bearer"
        and hmac.compare_digest(presented.encode(), token.encode())
    )


# ── Routes ──────────────────────────────────────────────────────────────────


@app.get("/", response_class=HTMLResponse)
def serve_viewer(request: Request):
    """Serve the live interactive viewer without embedding graph data."""
    data = _empty_graph_payload()
    return HTMLResponse(content=render_viewer_html(data, title="Live Attack Graph", mode="live"))


@app.get("/api/queries")
def list_queries():
    """List all available Cypher queries with metadata."""
    queries = discover_queries()
    return [
        {
            "id": q["id"],
            "filename": q["filename"],
            "name": q["name"],
            "purpose": q["purpose"],
            "category": q["category"],
            "severity": q["severity"],
            "parameters": q["parameters"],
        }
        for q in queries
    ]


@app.post("/api/queries/{query_id}/run")
def run_query_endpoint(
    query_id: str,
    body: QueryRunRequest | None = None,
    session=READ_SESSION_DEPENDENCY,
):
    """Execute a query by ID and return results as JSON."""
    queries = discover_queries()
    q = find_query(queries, query_id)
    if not q:
        raise HTTPException(status_code=404, detail=f"Query '{query_id}' not found")

    cypher = first_cypher_statement(q["cypher"])
    if _validate_api_cypher(cypher):
        logger.error("Configured query %s is not read-only", query_id)
        raise HTTPException(
            status_code=500,
            detail="Configured query is not read-only",
        )
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
    except (DriverError, Neo4jError) as err:
        logger.warning("Query %s failed: %s", query_id, err)
        raise HTTPException(
            status_code=400, detail="Query execution failed"
        ) from err

    truncated = len(rows) > MAX_ADHOC_CYPHER_ROWS
    rows = rows[:MAX_ADHOC_CYPHER_ROWS]
    return {
        "query": {
            "id": q["id"],
            "name": q["name"],
            "category": q["category"],
            "severity": q["severity"],
        },
        "rows": rows,
        "count": len(rows),
        "truncated": truncated,
    }


@app.get("/api/graph")
def get_graph(session=READ_SESSION_DEPENDENCY):
    """Return the full OpenGraph JSON for viewer refresh."""
    _hostname, data = _build_live_graph(session)
    return data


@app.post("/api/mark-owned")
def mark_owned_endpoint(body: MarkOwnedRequest, session=SESSION_DEPENDENCY):
    """Mark nodes as owned (compromised)."""
    timestamp = datetime.now(timezone.utc).isoformat()
    count = 0

    if body.bundle_ids:
        count += mark_by_bundle_id(session, body.bundle_ids, timestamp)
    if body.usernames:
        count += mark_by_username(session, body.usernames, timestamp)
    if body.label and body.keys:
        count += mark_by_label_key(session, body.label, body.keys, timestamp)

    if count == 0:
        raise HTTPException(status_code=404, detail="No matching nodes found")

    return {"marked": count, "timestamp": timestamp}


@app.post("/api/clear-owned")
def clear_owned_endpoint(body: ClearOwnedRequest, session=SESSION_DEPENDENCY):
    """Clear owned markers from nodes."""
    count = 0

    if body.all:
        count = clear_all(session)
    elif body.bundle_ids:
        count = clear_by_bundle_id(session, body.bundle_ids)
    elif body.usernames:
        count = clear_by_username(session, body.usernames)
    else:
        raise HTTPException(
            status_code=400, detail="Specify 'all', 'bundle_ids', or 'usernames'"
        )

    return {"cleared": count}


@app.get("/api/owned")
def get_owned(session=READ_SESSION_DEPENDENCY):
    """List all currently owned nodes."""
    owned = list_owned(session)
    results = []
    for item in owned:
        props = item.get("props", {})
        results.append(
            {
                "labels": item.get("labels", []),
                "name": props.get(
                    "name", props.get("bundle_id", props.get("label", "?"))
                ),
                "owned_at": props.get("owned_at", "?"),
                "properties": props,
            }
        )
    return {"owned": results, "count": len(results)}


@app.post("/api/tier-classify")
def tier_classify_endpoint(session=SESSION_DEPENDENCY):
    """Run tier classification on all Application nodes."""
    t0, t1, t2 = classify(session)

    return {
        "tier0": t0,
        "tier1": t1,
        "tier2": t2,
        "total": t0 + t1 + t2,
    }


def _limited_records(result) -> tuple[list[Any], bool]:
    records = []
    truncated = False
    for index, record in enumerate(result):
        if index >= MAX_ADHOC_CYPHER_ROWS:
            truncated = True
            break
        records.append(record)
    return records, truncated


# ── Ad-hoc Cypher endpoint ─────────────────────────────────────────────────


@app.post("/api/cypher")
def run_cypher_endpoint(body: CypherRequest, session=READ_SESSION_DEPENDENCY):
    """Execute an ad-hoc Cypher query (read-only).

    Accepts {"cypher": "MATCH ...", "params": {}}.
    Returns {"columns": [...], "rows": [...], "count": N}.
    Rejects write operations (CREATE, MERGE, SET, DELETE, etc.) with 403.
    """
    if len(body.cypher) > MAX_ADHOC_CYPHER_LENGTH:
        raise HTTPException(status_code=413, detail="Cypher query exceeds 10000 characters")
    error = _validate_adhoc_cypher(body.cypher)
    if error:
        raise HTTPException(status_code=403, detail=error)

    try:
        result = session.run(
            Query(body.cypher, timeout=ADHOC_CYPHER_TIMEOUT_SECONDS),
            body.params or {},
        )
        records, truncated = _limited_records(result)
        columns = list(records[0].keys()) if records else []
        rows = [dict(r) for r in records]
    except HTTPException:
        raise
    except (DriverError, Neo4jError) as err:
        logger.warning("Ad-hoc Cypher failed: %s", err)
        raise HTTPException(
            status_code=400, detail="Query execution failed"
        ) from err

    return {
        "columns": columns,
        "rows": rows,
        "count": len(rows),
        "truncated": truncated,
    }


# ── Helpers ─────────────────────────────────────────────────────────────────


def _get_hostname(session) -> str:
    """Get hostname from graph data. Returns 'rootstock' if the graph is empty."""
    result = session.run("MATCH (c:Computer) RETURN c.hostname AS hostname LIMIT 1")
    row = result.single()
    if row and row["hostname"]:
        return row["hostname"]
    # Fallback to scan_id prefix
    result = session.run(
        "MATCH (a:Application) WHERE a.scan_id IS NOT NULL "
        "RETURN a.scan_id AS scan_id LIMIT 1"
    )
    row = result.single()
    if row and row["scan_id"]:
        return row["scan_id"][:8]
    return "rootstock"


def _build_live_graph(session) -> tuple[str, dict[str, Any]]:
    """Build the live graph payload without request-time force layout.

    The static viewer can spend time on force-directed coordinates. The API path
    must stay bounded for large graphs, so missing positions use deterministic
    spiral coordinates that are stable enough for refreshes and tests.
    """
    hostname = _get_hostname(session)
    data = build_opengraph(
        session,
        hostname,
        maximum_nodes=INTERACTIVE_GRAPH_MAX_NODES + 1,
        maximum_edges=INTERACTIVE_GRAPH_MAX_EDGES + 1,
    )
    graph = data.get("graph", {})
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    if (
        len(nodes) > INTERACTIVE_GRAPH_MAX_NODES
        or len(edges) > INTERACTIVE_GRAPH_MAX_EDGES
    ):
        raise HTTPException(
            status_code=413,
            detail=(
                "Live graph exceeds the interactive limit of "
                f"{INTERACTIVE_GRAPH_MAX_NODES} nodes and "
                f"{INTERACTIVE_GRAPH_MAX_EDGES} edges"
            ),
        )
    for index, node in enumerate(nodes):
        if isinstance(node.get("x"), int | float) and isinstance(
            node.get("y"), int | float
        ):
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


def _validate_adhoc_cypher(cypher: str) -> str | None:
    return _validate_api_cypher(cypher)


def _validate_api_cypher(cypher: str) -> str | None:
    """Apply the viewer API's stricter no-procedure read-only policy."""
    cleaned = cypher_code_only(cypher)
    if _CALL_RE.search(cleaned):
        return "Procedures are not allowed through the viewer API"
    return validate_read_only_cypher(cypher)


def _is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_bind_host(host: str) -> None:
    """Reject every non-loopback bind for the alpha release surface."""
    if _is_loopback_host(host):
        return
    raise ValueError("Refusing non-loopback bind; alpha is loopback-only")


def _is_supported_neo4j_scheme(scheme: str) -> bool:
    return scheme in {"bolt", "neo4j", "bolt+s", "neo4j+s"}


def _has_neo4j_uri_credentials(parsed: SplitResult) -> bool:
    return bool(parsed.username or parsed.password)


def _has_loopback_neo4j_host(parsed: SplitResult) -> bool:
    return bool(parsed.hostname and _is_loopback_host(parsed.hostname))


def _has_neo4j_uri_suffix(parsed: SplitResult) -> bool:
    return bool(parsed.path not in {"", "/"} or parsed.query or parsed.fragment)


def _validate_neo4j_uri(uri: str) -> None:
    """Keep the alpha server's outbound database connection on loopback."""
    parsed = urlsplit(uri)
    if not _is_supported_neo4j_scheme(parsed.scheme):
        raise ValueError("Neo4j URI must use a supported Bolt/Neo4j scheme")
    if _has_neo4j_uri_credentials(parsed):
        raise ValueError("Neo4j URI must not contain credentials")
    if not _has_loopback_neo4j_host(parsed):
        raise ValueError("Refusing non-loopback Neo4j URI; alpha is local-only")
    if _has_neo4j_uri_suffix(parsed):
        raise ValueError("Neo4j URI must not contain a path, query, or fragment")


def _validate_api_token(token: str) -> None:
    if len(token.encode("utf-8")) < MIN_API_TOKEN_BYTES:
        raise ValueError(
            f"ROOTSTOCK_API_TOKEN must be at least {MIN_API_TOKEN_BYTES} bytes"
        )


# ── CLI ─────────────────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Rootstock REST API server")
    parser.add_argument(
        "--port", type=int, default=8000, help="Port to listen on (default: 8000)"
    )
    parser.add_argument(
        "--host", default="127.0.0.1", help="Host to bind to (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--neo4j", default="bolt://localhost:7687", help="Neo4j bolt URI"
    )
    parser.add_argument("--neo4j-user", default="neo4j", help="Neo4j username")
    return parser


def _configure_app_state(args: argparse.Namespace) -> bool:
    """Validate local-only startup inputs before exposing credentials in app state."""
    try:
        _validate_bind_host(args.host)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return False

    try:
        _validate_neo4j_uri(args.neo4j)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return False

    password = os.environ.get("NEO4J_PASSWORD")
    if not password:
        print(
            "ERROR: NEO4J_PASSWORD is required",
            file=sys.stderr,
        )
        return False

    api_token = os.environ.get("ROOTSTOCK_API_TOKEN")
    if not api_token:
        print("ERROR: ROOTSTOCK_API_TOKEN is required for /api/* routes", file=sys.stderr)
        return False
    try:
        _validate_api_token(api_token)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return False

    app.state.neo4j_uri = args.neo4j
    app.state.neo4j_user = args.neo4j_user
    app.state.neo4j_password = password
    app.state.api_token = api_token
    return True


def _run_server(args: argparse.Namespace) -> None:
    import uvicorn

    print(f"Starting Rootstock API server on {args.host}:{args.port}")
    print(f"  Viewer:  http://{args.host}:{args.port}/")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    if not _configure_app_state(args):
        return 1
    _run_server(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
