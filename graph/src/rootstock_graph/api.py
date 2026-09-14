#!/usr/bin/env python3
"""
rootstock-graph-api - Rootstock REST API server.

Thin HTTP wrapper over existing Rootstock functions: query execution,
owned-node marking, tier classification, and live graph data for the viewer.

Usage:
    rootstock-graph-api --port 8000
    rootstock-graph-api --port 8000 --neo4j bolt://localhost:7687

Opens at http://localhost:8000/ (viewer).

Exit code 0 on success, 1 on failure.
"""

from __future__ import annotations

import argparse
import importlib
import logging
import os
import sys
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
from neo4j import GraphDatabase, READ_ACCESS
from neo4j.exceptions import AuthError, ServiceUnavailable

# ── Imports from existing Rootstock modules ─────────────────────────────────


from .server_validation import (
    matches_api_token as _matches_api_token,
    validate_api_token as _validate_api_token,
    validate_bind_host as _validate_bind_host,
    validate_neo4j_uri as _validate_neo4j_uri,
)


# ── Request/Response models ─────────────────────────────────────────────────


class MarkOwnedRequest(BaseModel):
    bundle_ids: list[str] | None = None
    usernames: list[str] | None = None
    label: str | None = None
    keys: list[str] | None = None

    @model_validator(mode="after")
    def has_one_selector(self) -> "MarkOwnedRequest":
        generic_selector = self.label is not None or self.keys is not None
        selectors = sum(
            (
                bool(self.bundle_ids),
                bool(self.usernames),
                generic_selector,
            )
        )
        if selectors != 1:
            raise ValueError("Specify exactly one owned-node selector")
        if generic_selector and ((self.label is None) != (self.keys is None) or not self.keys):
            raise ValueError("label and keys must be supplied together")
        return self


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
    """Create separate writer and read-principal Neo4j drivers for the API."""
    uri = app.state.neo4j_uri
    user = app.state.neo4j_user
    password = app.state.neo4j_password
    read_user = app.state.neo4j_read_user
    read_password = app.state.neo4j_read_password
    writer_driver = None
    read_driver = None
    connected = False

    try:
        writer_driver = GraphDatabase.driver(uri, auth=(user, password))
        writer_driver.verify_connectivity()
        read_driver = GraphDatabase.driver(uri, auth=(read_user, read_password))
        read_driver.verify_connectivity()
        connected = True
    except ServiceUnavailable:
        print("ERROR: Cannot connect to Neo4j.", file=sys.stderr)
        sys.exit(1)
    except AuthError:
        print("ERROR: Neo4j authentication failed.", file=sys.stderr)
        sys.exit(1)
    finally:
        if not connected:
            if read_driver is not None:
                read_driver.close()
            if writer_driver is not None:
                writer_driver.close()

    app.state.writer_driver = writer_driver
    app.state.read_driver = read_driver
    print("Connected to Neo4j with distinct writer and read principals.")
    try:
        yield
    finally:
        read_driver.close()
        writer_driver.close()
        print("Neo4j connections closed.")


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


def get_session(request: Request):
    """Yield a mutation-capable session from the writer principal."""
    with request.app.state.writer_driver.session() as session:
        yield session


def get_read_session(request: Request):
    """Yield a read-routed session from the distinct read-only principal."""
    with request.app.state.read_driver.session(default_access_mode=READ_ACCESS) as session:
        yield session


SESSION_DEPENDENCY = Depends(get_session)
READ_SESSION_DEPENDENCY = Depends(get_read_session)

# Import after dependencies exist so route decorators attach to this stable facade.
_routes = importlib.import_module(".api_support.routes", __package__)


@app.middleware("http")
async def require_api_token(request: Request, call_next):
    """Protect all /api routes with a bearer token."""
    if request.url.path.startswith("/api/") and request.method != "OPTIONS":
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


# ── CLI ─────────────────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Rootstock REST API server")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to (default: 127.0.0.1)")
    parser.add_argument("--neo4j", default="bolt://localhost:7687", help="Neo4j bolt URI")
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

    credentials = _read_principal_credentials(args.neo4j_user)
    if credentials is None:
        return False
    password, read_user, read_password = credentials

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
    app.state.neo4j_read_user = read_user
    app.state.neo4j_read_password = read_password
    app.state.api_token = api_token
    return True


def _read_principal_credentials(writer_user: str) -> tuple[str, str, str] | None:
    password = os.environ.get("NEO4J_PASSWORD")
    if not password:
        print("ERROR: NEO4J_PASSWORD is required", file=sys.stderr)
        return None
    read_user = os.environ.get("NEO4J_READ_USER")
    if not read_user:
        print("ERROR: NEO4J_READ_USER is required for API read routes", file=sys.stderr)
        return None
    if read_user == writer_user:
        print("ERROR: NEO4J_READ_USER must differ from --neo4j-user", file=sys.stderr)
        return None
    read_password = os.environ.get("NEO4J_READ_PASSWORD")
    if not read_password:
        print("ERROR: NEO4J_READ_PASSWORD is required for API read routes", file=sys.stderr)
        return None
    return password, read_user, read_password


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
