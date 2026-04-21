"""
infer_group_capabilities.py — Infer capability edges from group membership.

Certain macOS local groups grant implicit capabilities:
  - _developer: enables debugger attachment (task_for_pid) to any process
  - com.apple.access_ssh: grants SSH access (links to RemoteAccessService)
  - com.apple.access_screensharing: grants Screen Sharing access

These capabilities are implicit from group membership but are not modeled
as explicit edges during import. This module creates CAN_DEBUG edges for
_developer group members.

Edge: User -[:CAN_DEBUG {inferred: true}]-> Application
      (for all running or injectable applications)
"""

from __future__ import annotations

from neo4j import Session


def infer(session: Session) -> int:
    """
    Infer CAN_DEBUG edges from _developer group members to applications.

    Members of the _developer group can attach a debugger (via task_for_pid)
    to any process not protected by SIP or hardened runtime with debugger
    restrictions. This enables memory inspection, code injection, and
    credential extraction.

    Returns the number of edges created or merged. Idempotent.
    """
    result = session.run(
        """
        MATCH (u:User)-[:MEMBER_OF]->(:LocalGroup {name: '_developer'})
        MATCH (a:Application)
        WHERE NOT coalesce(a.is_sip_protected, false)
          AND (a.hardened_runtime = false
               OR EXISTS {
                   MATCH (a)-[:HAS_ENTITLEMENT]->(:Entitlement {name: 'com.apple.security.get-task-allow'})
               })
        MERGE (u)-[r:CAN_DEBUG]->(a)
        SET r.inferred = true,
            r.reason = '_developer_group_membership'
        RETURN count(r) AS n
        """
    )
    return result.single()["n"]
