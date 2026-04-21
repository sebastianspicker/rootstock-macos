#!/usr/bin/env python3
"""
setup.py — Initialize the Rootstock Neo4j schema.

Usage:
    python3 graph/setup.py [--uri bolt://localhost:7687] [--user neo4j] [--password PASS]

Idempotent: safe to run multiple times.
"""

import argparse
import os
import sys
from pathlib import Path

from constants import NODE_KEY_PROPERTY

try:
    from neo4j import GraphDatabase
    from neo4j.exceptions import ServiceUnavailable, AuthError
except ImportError:
    print("ERROR: neo4j driver not installed. Run: pip3 install -r graph/requirements.txt", file=sys.stderr)
    sys.exit(1)

SCHEMA_DIR = Path(__file__).parent / "schema"
INIT_CYPHER = SCHEMA_DIR / "init-schema.cypher"
SEED_CYPHER = SCHEMA_DIR / "seed-tcc-services.cypher"


def parse_cypher_file(path: Path) -> list[str]:
    """Split a multi-statement Cypher file into individual statements."""
    text = path.read_text()
    statements = []
    for raw in text.split(";"):
        # Strip whitespace and inline comments
        lines = [
            line for line in raw.splitlines()
            if line.strip() and not line.strip().startswith("//")
        ]
        stmt = "\n".join(lines).strip()
        if stmt:
            statements.append(stmt)
    return statements


def run_cypher_file(session, path: Path) -> int:
    """Execute all statements in a Cypher file. Returns statement count."""
    statements = parse_cypher_file(path)
    for stmt in statements:
        session.run(stmt)
    return len(statements)


_ALLOWED_LABELS = frozenset(NODE_KEY_PROPERTY) | {"TCC_Permission"}


def count_nodes(session, label: str) -> int:
    if label not in _ALLOWED_LABELS:
        raise ValueError(f"Unknown label: {label}")
    result = session.run(f"MATCH (n:{label}) RETURN count(n) AS n")
    return result.single()["n"]


def count_constraints(session) -> int:
    result = session.run("SHOW CONSTRAINTS")
    return len(result.data())


def count_indexes(session) -> int:
    # Exclude constraint-backing indexes (type RANGE backing a UNIQUENESS constraint)
    result = session.run(
        "SHOW INDEXES WHERE type <> 'LOOKUP' AND owningConstraint IS NULL"
    )
    return len(result.data())


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialize Rootstock Neo4j schema")
    parser.add_argument("--uri", default="bolt://localhost:7687")
    parser.add_argument("--user", default="neo4j")
    parser.add_argument("--password", default=None, help="Neo4j password (or set NEO4J_PASSWORD)")
    args = parser.parse_args()

    password = args.password or os.environ.get("NEO4J_PASSWORD")
    if not password:
        print("ERROR: Neo4j password required via --password or NEO4J_PASSWORD env var", file=sys.stderr)
        return 1

    print(f"Connecting to Neo4j at {args.uri}...")
    try:
        driver = GraphDatabase.driver(args.uri, auth=(args.user, password))
        driver.verify_connectivity()
    except ServiceUnavailable:
        print(f"ERROR: Cannot connect to Neo4j at {args.uri}. Is it running?", file=sys.stderr)
        return 1
    except AuthError:
        print("ERROR: Authentication failed. Check --user / --password.", file=sys.stderr)
        return 1

    with driver.session() as session:
        print("Applying schema constraints and indexes...")
        run_cypher_file(session, INIT_CYPHER)

        print("Seeding TCC_Permission nodes...")
        run_cypher_file(session, SEED_CYPHER)

        n_constraints = count_constraints(session)
        n_indexes = count_indexes(session)
        n_tcc = count_nodes(session, "TCC_Permission")

    driver.close()
    print(
        f"Schema initialized with {n_constraints} constraints, "
        f"{n_indexes} indexes, {n_tcc} TCC services"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
