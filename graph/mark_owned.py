#!/usr/bin/env python3
"""
mark_owned.py — Mark graph nodes as "owned" (compromised) for attack path analysis.

Sets `owned: true` and `owned_at: <ISO timestamp>` on matched nodes.
Supports targeting by bundle_id, username, or label+key.

Usage:
    # Mark an app as owned
    python3 graph/mark_owned.py --bundle-id com.googlecode.iterm2

    # Mark a user as owned
    python3 graph/mark_owned.py --username admin

    # Mark any node by label and key
    python3 graph/mark_owned.py --label XPC_Service --key com.example.daemon.xpc

    # Mark multiple apps at once
    python3 graph/mark_owned.py --bundle-id com.googlecode.iterm2 com.tinyspeck.slackmacgap

Exit code 0 on success, 1 on failure.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

from neo4j_connection import add_neo4j_args, connect_from_args
from constants import OWNED_PROPERTY, OWNED_AT_PROPERTY, NODE_KEY_PROPERTY


# ── Marking functions ────────────────────────────────────────────────────────

def mark_by_bundle_id(session, bundle_ids: list[str], timestamp: str) -> int:
    """Mark Application nodes as owned by bundle_id. Returns count marked."""
    result = session.run(
        f"""
        UNWIND $ids AS bid
        MATCH (a:Application {{bundle_id: bid}})
        SET a.{OWNED_PROPERTY} = true, a.{OWNED_AT_PROPERTY} = $ts
        RETURN count(a) AS n
        """,
        ids=bundle_ids,
        ts=timestamp,
    )
    return result.single()["n"]


def mark_by_username(session, usernames: list[str], timestamp: str) -> int:
    """Mark User nodes as owned by username. Returns count marked."""
    result = session.run(
        f"""
        UNWIND $names AS uname
        MATCH (u:User {{name: uname}})
        SET u.{OWNED_PROPERTY} = true, u.{OWNED_AT_PROPERTY} = $ts
        RETURN count(u) AS n
        """,
        names=usernames,
        ts=timestamp,
    )
    return result.single()["n"]


def mark_by_label_key(session, label: str, keys: list[str], timestamp: str) -> int:
    """Mark nodes by Neo4j label and their unique key property. Returns count marked."""
    key_prop = NODE_KEY_PROPERTY.get(label)
    if not key_prop:
        print(f"ERROR: Unknown label '{label}'. Valid labels: {', '.join(sorted(NODE_KEY_PROPERTY))}", file=sys.stderr)
        return 0

    # SAFETY: `label` is safe to interpolate — NODE_KEY_PROPERTY.get(label) above
    # rejects any label not in the hardcoded allowlist (constants.py:23-43).
    # All allowlist keys are clean identifier strings (e.g. "Application", "User").
    result = session.run(
        f"""
        UNWIND $keys AS k
        MATCH (n:{label} {{{key_prop}: k}})
        SET n.{OWNED_PROPERTY} = true, n.{OWNED_AT_PROPERTY} = $ts
        RETURN count(n) AS n
        """,
        keys=keys,
        ts=timestamp,
    )
    return result.single()["n"]


def list_owned(session) -> list[dict]:
    """List all currently owned nodes."""
    result = session.run(
        f"""
        MATCH (n)
        WHERE n.{OWNED_PROPERTY} = true
        RETURN labels(n) AS labels, properties(n) AS props
        ORDER BY n.{OWNED_AT_PROPERTY}
        """
    )
    return [dict(r) for r in result]


# ── CLI ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Mark graph nodes as owned (compromised) for attack path analysis"
    )
    add_neo4j_args(parser)

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--bundle-id", nargs="+", help="Application bundle_id(s) to mark as owned")
    group.add_argument("--username", nargs="+", help="Username(s) to mark as owned")
    group.add_argument("--label", help="Neo4j label for generic node marking (use with --key)")
    group.add_argument("--list", action="store_true", help="List all currently owned nodes")

    parser.add_argument("--key", nargs="+", help="Unique key value(s) for --label mode")
    args = parser.parse_args()

    if args.label and not args.key:
        parser.error("--label requires --key")

    driver = connect_from_args(args)
    timestamp = datetime.now(timezone.utc).isoformat()

    with driver.session() as session:
        if args.list:
            owned = list_owned(session)
            if not owned:
                print("No owned nodes found.")
            else:
                print(f"Owned nodes ({len(owned)}):")
                for item in owned:
                    labels = ", ".join(item["labels"])
                    props = item["props"]
                    name = props.get("name", props.get("bundle_id", props.get("label", "?")))
                    ts = props.get(OWNED_AT_PROPERTY, "?")
                    print(f"  [{labels}] {name}  (owned_at: {ts})")
            driver.close()
            return 0

        if args.bundle_id:
            count = mark_by_bundle_id(session, args.bundle_id, timestamp)
            print(f"Marked {count} Application node(s) as owned.")
        elif args.username:
            count = mark_by_username(session, args.username, timestamp)
            print(f"Marked {count} User node(s) as owned.")
        elif args.label:
            count = mark_by_label_key(session, args.label, args.key, timestamp)
            print(f"Marked {count} {args.label} node(s) as owned.")
        else:
            count = 0

        if count == 0:
            print("WARNING: No matching nodes found in graph.", file=sys.stderr)

    driver.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
