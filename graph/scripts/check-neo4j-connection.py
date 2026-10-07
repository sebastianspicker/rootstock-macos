#!/usr/bin/env python3
"""
check-neo4j-connection.py - Verify Neo4j connectivity and schema state.

Usage:
    python3 graph/scripts/check-neo4j-connection.py [--uri bolt://localhost:7687] [--user neo4j]

Set writer credentials with NEO4J_PASSWORD and read-principal credentials with
NEO4J_READ_USER and NEO4J_READ_PASSWORD.
Exit code 0 on success, 1 on failure.
"""

import argparse
import os
import sys
from uuid import uuid4

try:
    from neo4j import GraphDatabase
    from neo4j import READ_ACCESS
    from neo4j.exceptions import (
        AuthError,
        ClientError,
        Neo4jError,
        ServiceUnavailable,
    )
except ImportError:
    print(
        "ERROR: neo4j driver not installed. Run: uv sync --project graph --extra dev",
        file=sys.stderr,
    )
    sys.exit(1)


def _required_credentials() -> tuple[str, str, str] | None:
    """Return writer password, read user, and read password, or None after reporting."""
    for name, label in (
        ("NEO4J_PASSWORD", "password"),
        ("NEO4J_READ_USER", "read user"),
        ("NEO4J_READ_PASSWORD", "read password"),
    ):
        if not os.environ.get(name):
            print(f"ERROR: Neo4j {label} required via {name}", file=sys.stderr)
            return None
    return (
        os.environ["NEO4J_PASSWORD"],
        os.environ["NEO4J_READ_USER"],
        os.environ["NEO4J_READ_PASSWORD"],
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Test Rootstock Neo4j connection")
    parser.add_argument("--uri", default="bolt://localhost:7687")
    parser.add_argument("--user", default="neo4j")
    args = parser.parse_args()

    credentials = _required_credentials()
    if credentials is None:
        return 1
    password, read_user, read_password = credentials

    writer_driver = None
    read_driver = None
    try:
        writer_driver = GraphDatabase.driver(args.uri, auth=(args.user, password))
        writer_driver.verify_connectivity()
        read_driver = GraphDatabase.driver(args.uri, auth=(read_user, read_password))
        read_driver.verify_connectivity()
    except ServiceUnavailable:
        print(f"FAIL: Cannot connect to Neo4j at {args.uri}", file=sys.stderr)
        _close_drivers(read_driver, writer_driver)
        return 1
    except AuthError:
        print("FAIL: Authentication failed.", file=sys.stderr)
        _close_drivers(read_driver, writer_driver)
        return 1

    try:
        with writer_driver.session() as session:
            # TCC nodes are evidence that the mutating pipeline completed.
            result = session.run("MATCH (t:TCC_Permission) RETURN count(t) AS n")
            n_tcc = result.single()["n"]

        with read_driver.session(default_access_mode=READ_ACCESS) as session:
            result = session.run("MATCH (n) RETURN count(n) AS n")
            if result.single()["n"] < 0:
                print("FAIL: Unexpected result from read-principal MATCH", file=sys.stderr)
                return 1
            if not _create_is_denied(session):
                if os.environ.get("ROOTSTOCK_REQUIRE_READONLY_PRINCIPAL") == "1":
                    return 1
                print(
                    "WARN: Read principal can write (expected on Neo4j Community, which has "
                    "no role-based access control). Set ROOTSTOCK_REQUIRE_READONLY_PRINCIPAL=1 "
                    "to fail this check on Enterprise."
                )
    finally:
        _close_drivers(read_driver, writer_driver)

    if n_tcc == 0:
        print(
            "WARN: Connected to Neo4j but no TCC_Permission nodes found. "
            "Run the pipeline with a scan file, for example: "
            "bash graph/pipeline.sh examples/demo-scan.json"
        )
        return 1

    print(
        f"Connected to Neo4j. Read principal can MATCH. Schema OK. Found {n_tcc} TCC_Permission nodes."
    )
    return 0


def _create_is_denied(session) -> bool:
    """Prove the read principal cannot write, rolling back even on misconfiguration."""
    transaction = session.begin_transaction()
    try:
        transaction.run(
            "CREATE (:RootstockReadPrincipalVerification {nonce: $nonce})",
            nonce=str(uuid4()),
        ).consume()
    except ClientError as exc:
        if getattr(exc, "code", "") == "Neo.ClientError.Security.Forbidden":
            return True
        print("Read-principal CREATE failed for an unexpected reason.", file=sys.stderr)
        return False
    except Neo4jError:
        print("Read-principal CREATE was not explicitly denied.", file=sys.stderr)
        return False
    else:
        print("Read principal allowed CREATE.", file=sys.stderr)
        return False
    finally:
        transaction.rollback()


def _close_drivers(read_driver, writer_driver) -> None:
    for driver in (read_driver, writer_driver):
        if driver is not None:
            driver.close()


if __name__ == "__main__":
    sys.exit(main())
