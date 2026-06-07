#!/usr/bin/env python3
"""
server.py — Rootstock REST API server.

Thin HTTP wrapper over existing Rootstock functions: query execution,
owned-node marking, tier classification, and live graph data for the viewer.

Usage:
    python3 graph/server.py --port 8000
    python3 graph/server.py --port 8000 --neo4j bolt://localhost:7687

Opens at http://localhost:8000/ (viewer) and http://localhost:8000/docs (OpenAPI).

Exit code 0 on success, 1 on failure.
"""

from __future__ import annotations

import argparse
import html as html_mod
import ipaddress
import json
import logging
import math
import os
import re
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from neo4j import GraphDatabase, Query, READ_ACCESS
from neo4j.exceptions import ServiceUnavailable, AuthError

# ── Imports from existing Rootstock modules ─────────────────────────────────

sys.path.insert(0, str(Path(__file__).parent))

from query_runner import discover_queries, find_query
from utils import first_cypher_statement, run_query, validate_read_only_cypher

from opengraph_export import build_opengraph  # noqa: E402
from mark_owned import (  # noqa: E402
    mark_by_bundle_id,
    mark_by_username,
    mark_by_label_key,
    list_owned,
)
from clear_owned import clear_all, clear_by_bundle_id, clear_by_username  # noqa: E402
from tier_classification import classify  # noqa: E402


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
        print(f"ERROR: Cannot connect to Neo4j at {uri}", file=sys.stderr)
        sys.exit(1)
    except AuthError:
        print("ERROR: Neo4j authentication failed.", file=sys.stderr)
        sys.exit(1)

    app.state.driver = driver
    print(f"Connected to Neo4j at {uri}")
    yield
    driver.close()
    print("Neo4j connection closed.")


app = FastAPI(
    title="Rootstock API",
    description="REST API for Rootstock macOS attack graph",
    version="1.0.0",
    lifespan=lifespan,
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
_DBMS_CALL_RE = re.compile(r"\bCALL\s+dbms\.", re.IGNORECASE)


def get_session(request: Request):
    """Yield a Neo4j session from the app-level driver."""
    with request.app.state.driver.session() as session:
        yield session


def get_read_session(request: Request):
    """Yield a read-only Neo4j session — Neo4j rejects writes at the driver level."""
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
        if not token or auth_header != f"Bearer {token}":
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing or invalid bearer token"},
                headers={"WWW-Authenticate": "Bearer"},
            )
    return await call_next(request)


# ── Routes ──────────────────────────────────────────────────────────────────


@app.get("/", response_class=HTMLResponse)
def serve_viewer(request: Request):
    """Serve the live interactive viewer without embedding graph data."""
    template_path = Path(__file__).parent / "viewer_template.html"
    template = template_path.read_text()

    data = _empty_graph_payload()
    safe_json = json.dumps(data, ensure_ascii=True).replace("</", "<\\/")
    title = "Live Attack Graph"

    # Inject live mode flag and replace template placeholders
    live_inject = "const __ROOTSTOCK_LIVE__ = true;\nconst API_BASE = '';\n"
    html = template.replace("{{VIEWER_TITLE}}", html_mod.escape(title))
    html = html.replace(
        "let DATA = {{VIEWER_DATA}};",
        live_inject + "let DATA = " + safe_json + ";",
    )

    return HTMLResponse(content=html)


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
    params = body.params if body else {}
    try:
        rows = run_query(session, cypher, params or {})
    except Exception as err:
        logger.warning("Query %s failed: %s", query_id, err)
        raise HTTPException(
            status_code=400, detail="Query execution failed"
        ) from err

    return {
        "query": {
            "id": q["id"],
            "name": q["name"],
            "category": q["category"],
            "severity": q["severity"],
        },
        "rows": rows,
        "count": len(rows),
    }


@app.get("/api/graph")
def get_graph(session=SESSION_DEPENDENCY):
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
def get_owned(session=SESSION_DEPENDENCY):
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
    except Exception as err:
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
    data = build_opengraph(session, hostname)
    graph = data.get("graph", {})
    for index, node in enumerate(graph.get("nodes", [])):
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
    cleaned = re.sub(r"/\*.*?\*/", " ", cypher, flags=re.DOTALL)
    cleaned = "\n".join(
        line for line in cleaned.splitlines() if not line.strip().startswith("//")
    )
    cleaned = re.sub(r"'(?:[^'\\]|\\.)*'", "''", cleaned)
    cleaned = re.sub(r'"(?:[^"\\]|\\.)*"', '""', cleaned)
    if _DBMS_CALL_RE.search(cleaned):
        return "dbms procedures are not allowed in ad-hoc Cypher"
    return validate_read_only_cypher(cypher)


def _is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_bind_host(host: str, allow_remote: bool) -> None:
    if allow_remote or _is_loopback_host(host):
        return
    raise ValueError("Refusing non-loopback bind without --allow-remote")


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
        "--allow-remote",
        action="store_true",
        help="Allow binding to a non-loopback host",
    )
    parser.add_argument(
        "--neo4j", default="bolt://localhost:7687", help="Neo4j bolt URI"
    )
    parser.add_argument("--neo4j-user", default="neo4j", help="Neo4j username")
    parser.add_argument(
        "--neo4j-password", default=None, help="Neo4j password (or set NEO4J_PASSWORD)"
    )
    return parser


def _configure_app_state(args: argparse.Namespace) -> bool:
    try:
        _validate_bind_host(args.host, args.allow_remote)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return False

    password = args.neo4j_password or os.environ.get("NEO4J_PASSWORD")
    if not password:
        print(
            "ERROR: Neo4j password required via --neo4j-password or NEO4J_PASSWORD env var",
            file=sys.stderr,
        )
        return False

    api_token = os.environ.get("ROOTSTOCK_API_TOKEN")
    if not api_token:
        print("ERROR: ROOTSTOCK_API_TOKEN is required for /api/* routes", file=sys.stderr)
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
    print(f"  OpenAPI: http://{args.host}:{args.port}/docs")
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
