"""
neo4j_connection.py — Shared Neo4j connection helpers for Rootstock CLIs.

Provides unified argparse arguments, driver creation, and error handling
used by import.py, infer.py, report.py, and query_runner.py.

Importing this module validates that required dependencies (neo4j, pydantic)
are installed, providing a friendly error message if not.
"""

from __future__ import annotations

import argparse
import os
import sys

try:
    from neo4j import GraphDatabase
    from neo4j.exceptions import ServiceUnavailable, AuthError
except ImportError:
    print(
        "ERROR: neo4j driver not installed. Run: pip3 install -r graph/requirements.txt",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    import pydantic  # noqa: F401
except ImportError:
    print(
        "ERROR: pydantic not installed. Run: pip3 install -r graph/requirements.txt",
        file=sys.stderr,
    )
    sys.exit(1)


def add_neo4j_args(parser: argparse.ArgumentParser) -> None:
    """Add the standard --neo4j, --neo4j-user, --neo4j-password arguments."""
    parser.add_argument("--neo4j", default="bolt://localhost:7687", dest="uri",
                        help="Neo4j bolt URI (default: bolt://localhost:7687)")
    parser.add_argument("--neo4j-user", default="neo4j", dest="neo4j_user",
                        help="Neo4j username (default: neo4j)")
    parser.add_argument("--neo4j-password", default=None, dest="neo4j_password",
                        help="Neo4j password (or set NEO4J_PASSWORD env var)")


def connect(uri: str, username: str, password: str, *, quiet: bool = False):
    """
    Create and verify a Neo4j driver connection.

    Returns the driver on success, or calls sys.exit(1) on failure.
    """
    if not quiet:
        print(f"Connecting to Neo4j at {uri}...")
    try:
        driver = GraphDatabase.driver(uri, auth=(username, password))
        driver.verify_connectivity()
    except ServiceUnavailable:
        print(f"ERROR: Cannot connect to Neo4j at {uri}", file=sys.stderr)
        sys.exit(1)
    except AuthError:
        print("ERROR: Authentication failed. Check --neo4j-user / --neo4j-password.", file=sys.stderr)
        sys.exit(1)
    return driver


def connect_from_args(args):
    """Create a driver from parsed argparse namespace (expects .uri, .neo4j_user, .neo4j_password)."""
    password = args.neo4j_password or os.environ.get("NEO4J_PASSWORD")
    if not password:
        print("ERROR: Neo4j password required via --neo4j-password or NEO4J_PASSWORD env var",
              file=sys.stderr)
        sys.exit(1)
    return connect(args.uri, args.neo4j_user, password)
