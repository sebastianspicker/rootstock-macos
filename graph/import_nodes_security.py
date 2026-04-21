"""import_nodes_security.py — Security infrastructure node imports."""

from __future__ import annotations

import json
import logging

from neo4j import Session

from models import (
    LocalGroupData,
    RemoteAccessServiceData,
    FirewallStatusData,
    LoginSessionData,
    AuthorizationRightData,
    AuthorizationPluginData,
    SystemExtensionData,
    SudoersRuleData,
)

logger = logging.getLogger(__name__)

# Service-to-group mapping for ACCESSIBLE_BY edge inference.
_REMOTE_ACCESS_GROUP_MAP = [
    {"svc_name": "ssh", "group_name": "com.apple.access_ssh"},
    {"svc_name": "screen_sharing", "group_name": "com.apple.access_screensharing"},
]

_FIREWALL_POLICY_NAME = "default"


def import_local_groups(
    session: Session, groups: list[LocalGroupData], scan_id: str | None = None
) -> tuple[int, int]:
    """
    MERGE LocalGroup nodes and MEMBER_OF relationships from User → LocalGroup.

    Returns (group_nodes, member_of_edges).
    """
    if not groups:
        return 0, 0

    records = [
        {
            "name": g.name,
            "gid": g.gid,
            "members": g.members,
        }
        for g in groups
    ]

    # MERGE LocalGroup nodes
    session.run(
        """
        UNWIND $records AS r
        MERGE (g:LocalGroup {name: r.name})
        SET g.gid = CASE WHEN r.gid > 0 THEN r.gid ELSE coalesce(g.gid, r.gid) END
        """,
        records=records,
    )

    # MEMBER_OF: User → LocalGroup
    result = session.run(
        """
        UNWIND $records AS r
        WITH r WHERE size(r.members) > 0
        UNWIND r.members AS username
        MATCH (g:LocalGroup {name: r.name})
        MERGE (u:User {name: username})
        MERGE (u)-[rel:MEMBER_OF]->(g)
        SET rel.scan_id = $scan_id
        RETURN count(rel) AS n
        """,
        records=records,
        scan_id=scan_id,
    )
    edges = result.single()["n"]

    return len(groups), edges


def import_remote_access_services(
    session: Session, services: list[RemoteAccessServiceData]
) -> tuple[int, int]:
    """
    MERGE RemoteAccessService nodes and ACCESSIBLE_BY edges from service to Users
    via group membership (com.apple.access_ssh / com.apple.access_screensharing).

    Returns (service_nodes, accessible_by_edges).
    """
    if not services:
        return 0, 0

    records = [
        {
            "service": s.service,
            "enabled": s.enabled,
            "port": s.port,
            # Stored as config_json (not config) because Neo4j doesn't support
            # map properties. Cypher queries must use s.config_json, not s.config.
            "config_json": json.dumps(s.config) if s.config else "{}",
        }
        for s in services
    ]

    session.run(
        """
        UNWIND $records AS r
        MERGE (s:RemoteAccessService {service: r.service})
        SET s.enabled     = r.enabled,
            s.port        = r.port,
            s.config_json = r.config_json
        """,
        records=records,
    )

    # ACCESSIBLE_BY edges: cross-reference group membership
    result = session.run(
        """
        UNWIND $mappings AS m
        MATCH (s:RemoteAccessService {service: m.svc_name})
        WHERE s.enabled = true
        MATCH (u:User)-[:MEMBER_OF]->(:LocalGroup {name: m.group_name})
        MERGE (s)-[rel:ACCESSIBLE_BY]->(u)
        RETURN count(rel) AS n
        """,
        mappings=_REMOTE_ACCESS_GROUP_MAP,
    )
    total_edges = result.single()["n"]

    return len(services), total_edges


def import_firewall_status(
    session: Session, statuses: list[FirewallStatusData], scan_id: str | None = None
) -> tuple[int, int]:
    """
    MERGE FirewallPolicy node and HAS_FIREWALL_RULE edges to Applications.

    Returns (firewall_nodes, has_firewall_rule_edges).
    """
    if not statuses:
        return 0, 0

    fw_records = [
        {
            "name": _FIREWALL_POLICY_NAME,
            "enabled": s.enabled,
            "stealth_mode": s.stealth_mode,
            "allow_signed": s.allow_signed,
            "allow_built_in": s.allow_built_in,
        }
        for s in statuses
    ]

    session.run(
        """
        UNWIND $records AS r
        MERGE (f:FirewallPolicy {name: r.name})
        SET f.enabled       = r.enabled,
            f.stealth_mode  = r.stealth_mode,
            f.allow_signed  = r.allow_signed,
            f.allow_built_in = r.allow_built_in
        """,
        records=fw_records,
    )

    # Flatten app rules across all statuses
    rule_records = [
        {
            "bundle_id": rule.bundle_id,
            "allow_incoming": rule.allow_incoming,
        }
        for s in statuses
        for rule in s.app_rules
    ]

    if not rule_records:
        return len(statuses), 0

    # HAS_FIREWALL_RULE: Application → FirewallPolicy
    result = session.run(
        """
        UNWIND $records AS r
        MATCH (a:Application {bundle_id: r.bundle_id})
        WHERE $scan_id IS NULL OR a.scan_id = $scan_id
        MATCH (f:FirewallPolicy {name: $policy_name})
        MERGE (a)-[rel:HAS_FIREWALL_RULE]->(f)
        SET rel.allow_incoming = r.allow_incoming
        RETURN count(rel) AS n
        """,
        records=rule_records,
        policy_name=_FIREWALL_POLICY_NAME,
        scan_id=scan_id,
    )
    edges = result.single()["n"]

    return len(statuses), edges


def import_login_sessions(
    session: Session, sessions: list[LoginSessionData], hostname: str = "localhost"
) -> tuple[int, int]:
    """
    MERGE LoginSession nodes and HAS_SESSION relationships from User → LoginSession.

    Returns (session_nodes, has_session_edges).
    """
    if not sessions:
        return 0, 0

    records = [
        {
            "username": s.username,
            "terminal": s.terminal,
            "login_time": s.login_time,
            "session_type": s.session_type,
            "hostname": hostname,
        }
        for s in sessions
    ]

    # MERGE LoginSession nodes (terminal + hostname is unique per active session)
    session.run(
        """
        UNWIND $records AS r
        MERGE (s:LoginSession {terminal: r.terminal, hostname: r.hostname})
        SET s.username     = r.username,
            s.login_time   = r.login_time,
            s.session_type = r.session_type
        """,
        records=records,
    )

    # HAS_SESSION: User → LoginSession
    result = session.run(
        """
        UNWIND $records AS r
        MATCH (s:LoginSession {terminal: r.terminal, hostname: r.hostname})
        MERGE (u:User {name: r.username})
        MERGE (u)-[rel:HAS_SESSION]->(s)
        RETURN count(rel) AS n
        """,
        records=records,
    )
    edges = result.single()["n"]

    return len(sessions), edges


def import_authorization_rights(
    session: Session, rights: list[AuthorizationRightData]
) -> int:
    """MERGE AuthorizationRight nodes. Returns count."""
    if not rights:
        return 0

    records = [
        {
            "name": r.name,
            "rule": r.rule,
            "allow_root": r.allow_root,
            "require_authentication": r.require_authentication,
        }
        for r in rights
    ]

    session.run(
        """
        UNWIND $records AS r
        MERGE (ar:AuthorizationRight {name: r.name})
        SET ar.rule                   = r.rule,
            ar.allow_root             = r.allow_root,
            ar.require_authentication = r.require_authentication
        """,
        records=records,
    )
    return len(records)


def import_authorization_plugins(
    session: Session, plugins: list[AuthorizationPluginData]
) -> int:
    """MERGE AuthorizationPlugin nodes. Returns count."""
    if not plugins:
        return 0

    records = [
        {
            "name": p.name,
            "path": p.path,
            "team_id": p.team_id,
        }
        for p in plugins
    ]

    session.run(
        """
        UNWIND $records AS r
        MERGE (ap:AuthorizationPlugin {name: r.name})
        SET ap.path    = r.path,
            ap.team_id = r.team_id
        """,
        records=records,
    )
    return len(records)


def import_system_extensions(
    session: Session, extensions: list[SystemExtensionData]
) -> int:
    """MERGE SystemExtension nodes. Returns count."""
    if not extensions:
        return 0

    records = [
        {
            "identifier": e.identifier,
            "team_id": e.team_id,
            "extension_type": e.extension_type,
            "enabled": e.enabled,
            "subscribed_events": e.subscribed_events,
        }
        for e in extensions
    ]

    session.run(
        """
        UNWIND $records AS r
        MERGE (se:SystemExtension {identifier: r.identifier})
        SET se.team_id            = r.team_id,
            se.extension_type     = r.extension_type,
            se.enabled            = r.enabled,
            se.subscribed_events  = r.subscribed_events
        """,
        records=records,
    )
    return len(records)


def import_sudoers_rules(
    session: Session, rules: list[SudoersRuleData]
) -> tuple[int, int]:
    """
    MERGE SudoersRule nodes and SUDO_NOPASSWD edges from User → SudoersRule.
    Returns (rule_nodes, sudo_nopasswd_edges).
    """
    if not rules:
        return 0, 0

    records = [
        {
            "user": r.user,
            "host": r.host,
            "command": r.command,
            "nopasswd": r.nopasswd,
            "key": f"{r.user}:{r.host}:{r.command}",
        }
        for r in rules
    ]

    session.run(
        """
        UNWIND $records AS r
        MERGE (sr:SudoersRule {key: r.key})
        SET sr.user     = r.user,
            sr.host     = r.host,
            sr.command  = r.command,
            sr.nopasswd = r.nopasswd
        """,
        records=records,
    )

    # SUDO_NOPASSWD: User → SudoersRule (only for NOPASSWD rules)
    result = session.run(
        """
        UNWIND $records AS r
        WITH r WHERE r.nopasswd = true
        MATCH (sr:SudoersRule {key: r.key})
        MERGE (u:User {name: r.user})
        MERGE (u)-[rel:SUDO_NOPASSWD]->(sr)
        RETURN count(rel) AS n
        """,
        records=records,
    )
    edges = result.single()["n"]

    return len(rules), edges
