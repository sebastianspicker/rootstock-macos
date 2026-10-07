"""infer_common_local.py - Shared Cypher for scoping inference-created users to a host."""

from __future__ import annotations

# CriticalFile nodes are keyed by path only and carry no scan_id or Computer link, so
# the owning host cannot be derived from them. When exactly one Computer exists the
# host is unambiguous and the freshly merged User is attached to it; with several
# Computers no edge is guessed (avoids cross-host over-linking).
# Expects a bound ``u`` (User) and leaves ``u`` bound for the following clauses.
LINK_USER_TO_SOLE_COMPUTER = """
        CALL (u) {
            MATCH (c:Computer)
            WITH collect(c) AS computers
            WHERE size(computers) = 1
            UNWIND computers AS c
            MERGE (u)-[:LOCAL_TO]->(c)
        }
"""
