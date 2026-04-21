"""
infer_mdm_overgrant.py — Flag MDM profiles that grant TCC permissions to scripting interpreters.

MDM profiles that grant any TCC permission to Terminal, Python, osascript, or
other scripting interpreters effectively grant attackers unrestricted access
through script injection.

Edge: MDM_Profile -[:MDM_OVERGRANT {inferred: true}]-> TCC_Permission
"""

from __future__ import annotations

from neo4j import Session

# Bundle IDs of common scripting interpreters that should not have FDA via MDM
_SCRIPTING_INTERPRETERS = [
    "com.apple.Terminal",
    "org.python.python",
    "com.apple.ScriptEditor2",
    "com.apple.osascript",
    "com.googlecode.iterm2",
    "io.alacritty",
    "com.github.wez.wezterm",
]


def infer(session: Session) -> int:
    """
    Infer MDM_OVERGRANT edges from MDM profiles that grant any TCC permission
    to scripting interpreters. Returns edge count. Idempotent.
    """
    result = session.run(
        """
        MATCH (m:MDM_Profile)-[c:CONFIGURES]->(t:TCC_Permission)
        WHERE c.allowed = true
          AND c.bundle_id IN $interpreters
        MERGE (m)-[r:MDM_OVERGRANT]->(t)
        SET r.inferred = true,
            r.flagged_bundle_id = c.bundle_id,
            r.reason = 'scripting_interpreter_with_tcc_grant'
        RETURN count(r) AS n
        """,
        interpreters=_SCRIPTING_INTERPRETERS,
    )
    return result.single()["n"]
