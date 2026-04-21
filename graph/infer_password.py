"""
infer_password.py — Infer CAN_CHANGE_PASSWORD edges from admin/sudo privileges.

macOS admin-group members can change any non-admin user's password via
`dscl . -passwd`. Users with SUDO_NOPASSWD ALL can change *any* user's
password. This is the macOS analog of BloodHound's ForceChangePassword edge.

Edge: User -[:CAN_CHANGE_PASSWORD {inferred: true}]-> User
"""

from __future__ import annotations

from neo4j import Session


def infer(session: Session) -> int:
    """
    Infer CAN_CHANGE_PASSWORD edges from two privilege sources:

    1. Admin group members → all non-admin users (via dscl . -passwd)
    2. SUDO_NOPASSWD ALL holders → all other users (via sudo dscl)

    Returns the total number of edges created or merged. Idempotent.
    """
    # Rule 1: admin group → non-admin users
    r1 = session.run(
        """
        MATCH (admin_user:User)-[:MEMBER_OF]->(:LocalGroup {name: 'admin'})
        MATCH (target_user:User)
        WHERE target_user.name <> admin_user.name
          AND NOT (target_user)-[:MEMBER_OF]->(:LocalGroup {name: 'admin'})
        MERGE (admin_user)-[r:CAN_CHANGE_PASSWORD]->(target_user)
        SET r.inferred = true, r.reason = 'admin_group_dscl_passwd'
        RETURN count(r) AS n
        """
    )
    n1 = r1.single()["n"]

    # Rule 2: SUDO_NOPASSWD ALL → any other user
    r2 = session.run(
        """
        MATCH (u:User)-[:SUDO_NOPASSWD]->(sr:SudoersRule)
        WHERE sr.command = 'ALL'
        MATCH (target:User)
        WHERE target.name <> u.name
        MERGE (u)-[r:CAN_CHANGE_PASSWORD]->(target)
        SET r.inferred = true, r.reason = 'sudo_nopasswd_dscl'
        RETURN count(r) AS n
        """
    )
    n2 = r2.single()["n"]

    return n1 + n2
