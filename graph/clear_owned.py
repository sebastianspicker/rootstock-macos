#!/usr/bin/env python3
"""
clear_owned.py — Reset ownership markers from graph nodes.

Removes `owned` and `owned_at` properties. Can target specific nodes or clear all.

Usage:
    # Clear all owned markers
    python3 graph/clear_owned.py --all

    # Clear specific app(s)
    python3 graph/clear_owned.py --bundle-id com.googlecode.iterm2

    # Clear specific user(s)
    python3 graph/clear_owned.py --username admin

Exit code 0 on success, 1 on failure.
"""

from __future__ import annotations

import argparse
import sys

from neo4j_connection import add_neo4j_args, connect_from_args
from constants import OWNED_PROPERTY, OWNED_AT_PROPERTY, TIER_PROPERTY


def clear_all(session) -> int:
    """Remove owned markers from all nodes. Returns count cleared."""
    result = session.run(
        f"""
        MATCH (n)
        WHERE n.{OWNED_PROPERTY} = true
        REMOVE n.{OWNED_PROPERTY}, n.{OWNED_AT_PROPERTY}
        RETURN count(n) AS n
        """
    )
    return result.single()["n"]


def clear_by_bundle_id(session, bundle_ids: list[str]) -> int:
    """Remove owned markers from Application nodes by bundle_id."""
    result = session.run(
        f"""
        UNWIND $ids AS bid
        MATCH (a:Application {{bundle_id: bid}})
        WHERE a.{OWNED_PROPERTY} = true
        REMOVE a.{OWNED_PROPERTY}, a.{OWNED_AT_PROPERTY}
        RETURN count(a) AS n
        """,
        ids=bundle_ids,
    )
    return result.single()["n"]


def clear_by_username(session, usernames: list[str]) -> int:
    """Remove owned markers from User nodes by username."""
    result = session.run(
        f"""
        UNWIND $names AS uname
        MATCH (u:User {{name: uname}})
        WHERE u.{OWNED_PROPERTY} = true
        REMOVE u.{OWNED_PROPERTY}, u.{OWNED_AT_PROPERTY}
        RETURN count(u) AS n
        """,
        names=usernames,
    )
    return result.single()["n"]


def clear_tiers(session) -> int:
    """Remove tier classification from all Application nodes."""
    result = session.run(
        f"""
        MATCH (a:Application)
        WHERE a.{TIER_PROPERTY} IS NOT NULL
        REMOVE a.{TIER_PROPERTY}
        RETURN count(a) AS n
        """
    )
    return result.single()["n"]


# ── CLI ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Clear ownership markers from graph nodes"
    )
    add_neo4j_args(parser)

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true", help="Clear all owned markers")
    group.add_argument("--bundle-id", nargs="+", help="Clear specific Application(s)")
    group.add_argument("--username", nargs="+", help="Clear specific User(s)")
    group.add_argument("--tiers", action="store_true", help="Clear tier classification from all apps")

    args = parser.parse_args()
    driver = connect_from_args(args)

    with driver.session() as session:
        if args.all:
            count = clear_all(session)
            print(f"Cleared ownership from {count} node(s).")
        elif args.bundle_id:
            count = clear_by_bundle_id(session, args.bundle_id)
            print(f"Cleared ownership from {count} Application node(s).")
        elif args.username:
            count = clear_by_username(session, args.username)
            print(f"Cleared ownership from {count} User node(s).")
        elif args.tiers:
            count = clear_tiers(session)
            print(f"Cleared tier classification from {count} Application node(s).")

    driver.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
