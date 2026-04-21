#!/usr/bin/env python3
"""
test_connection.py — Verify Neo4j connectivity and schema state.

Usage:
    python3 graph/test_connection.py [--uri bolt://localhost:7687] [--user neo4j] [--password <pw>]

Password can also be set via the NEO4J_PASSWORD environment variable.
Exit code 0 on success, 1 on failure.
"""

import argparse
import os
import sys

try:
    from neo4j import GraphDatabase
    from neo4j.exceptions import ServiceUnavailable, AuthError
except ImportError:
    print("ERROR: neo4j driver not installed. Run: pip3 install -r graph/requirements.txt", file=sys.stderr)
    sys.exit(1)


def main() -> int:
    parser = argparse.ArgumentParser(description="Test Rootstock Neo4j connection")
    parser.add_argument("--uri", default="bolt://localhost:7687")
    parser.add_argument("--user", default="neo4j")
    parser.add_argument("--password", default=None, help="Neo4j password (or set NEO4J_PASSWORD)")
    args = parser.parse_args()

    password = args.password or os.environ.get("NEO4J_PASSWORD")
    if not password:
        print("ERROR: Neo4j password required via --password or NEO4J_PASSWORD env var",
              file=sys.stderr)
        return 1

    try:
        driver = GraphDatabase.driver(args.uri, auth=(args.user, password))
        driver.verify_connectivity()
    except ServiceUnavailable:
        print(f"FAIL: Cannot connect to Neo4j at {args.uri}", file=sys.stderr)
        return 1
    except AuthError:
        print("FAIL: Authentication failed.", file=sys.stderr)
        return 1

    with driver.session() as session:
        # Basic connectivity
        result = session.run("RETURN 1 AS ok")
        assert result.single()["ok"] == 1, "Unexpected result from RETURN 1"

        # TCC nodes
        result = session.run("MATCH (t:TCC_Permission) RETURN count(t) AS n")
        n_tcc = result.single()["n"]

    driver.close()

    if n_tcc == 0:
        print("WARN: Connected to Neo4j but no TCC_Permission nodes found. Run: python3 graph/setup.py")
        return 1

    print(f"Connected to Neo4j. Schema OK. Found {n_tcc} TCC_Permission nodes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
