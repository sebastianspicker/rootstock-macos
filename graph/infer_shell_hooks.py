"""
infer_shell_hooks.py — Infer shell hook injection attack paths.

Creates CAN_INJECT_SHELL edges from Users to CriticalFile nodes
where the shell hook file is writable by that user.

A writable shell hook (.zshrc, .bashrc, etc.) means an attacker controlling
that user can inject arbitrary code that runs on every interactive session.

All inferred edges carry {inferred: true}.
"""

from __future__ import annotations

from neo4j import Session


def infer(session: Session) -> int:
    """
    Infer shell hook injection paths. Returns edges created.
    Idempotent: uses MERGE, safe to re-run.
    """
    result = session.run(
        """
        MATCH (cf:CriticalFile)
        WHERE cf.category = 'shell_hook'
          AND cf.is_writable_by_non_root = true
        MERGE (u:User {name: cf.owner})
        MERGE (u)-[r:CAN_INJECT_SHELL]->(cf)
        SET r.inferred = true,
            r.reason = 'writable_shell_hook'
        RETURN count(r) AS n
        """
    )
    return result.single()["n"]
