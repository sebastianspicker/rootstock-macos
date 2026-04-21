#!/usr/bin/env python3
"""
bloodhound_import.py — Import SharpHound JSON ZIP archives into Rootstock Neo4j.

Parses SharpHound ZIP exports (users.json, groups.json) and creates:
  - (:ADUser) nodes with SID, name, domain, enabled status
  - (:ADUser)-[:SAME_IDENTITY]->(:User) edges by case-insensitive username match
  - (:ADUser)-[:AD_MEMBER_OF]->(:ADGroup) edges from group membership data

This enables cross-domain attack path queries correlating AD principals
with macOS local users, e.g. "AD domain admin -> macOS local admin -> TCC grant".

Usage:
    python3 graph/bloodhound_import.py --zip sharphound-export.zip [--neo4j bolt://localhost:7687]

Exit code 0 on success, 1 on failure.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import zipfile
from pathlib import Path

from neo4j_connection import add_neo4j_args, connect_from_args


# ── ZIP parsing ──────────────────────────────────────────────────────────────


def _find_json_in_zip(zf: zipfile.ZipFile, suffix: str) -> str | None:
    """Find a JSON file in the ZIP whose name ends with the given suffix."""
    for name in zf.namelist():
        basename = name.rsplit("/", 1)[-1] if "/" in name else name
        if basename.lower().endswith(suffix.lower()):
            return name
    return None


def parse_sharphound_zip(zip_path: str) -> dict:
    """Extract users.json and groups.json data from a SharpHound ZIP archive.

    Args:
        zip_path: Path to the SharpHound ZIP file.

    Returns:
        Dict with 'users' and 'groups' keys containing parsed JSON data lists.

    Raises:
        FileNotFoundError: If the ZIP file does not exist.
        zipfile.BadZipFile: If the file is not a valid ZIP archive.
        ValueError: If neither users.json nor groups.json is found.
    """
    zip_path_obj = Path(zip_path)
    if not zip_path_obj.exists():
        raise FileNotFoundError(f"ZIP file not found: {zip_path}")

    result: dict[str, list] = {"users": [], "groups": []}

    MAX_DECOMPRESSED = 100 * 1024 * 1024  # 100 MB per JSON file

    with zipfile.ZipFile(zip_path, "r") as zf:
        # Check decompressed sizes and reject path traversal attempts
        for info in zf.infolist():
            if info.file_size > MAX_DECOMPRESSED:
                raise ValueError(
                    f"Entry {info.filename} decompressed size "
                    f"({info.file_size} bytes) exceeds limit"
                )
            if os.path.isabs(info.filename) or ".." in info.filename.split("/"):
                raise ValueError(f"Unsafe path in ZIP: {info.filename}")

        users_file = _find_json_in_zip(zf, "users.json")
        groups_file = _find_json_in_zip(zf, "groups.json")

        if not users_file and not groups_file:
            raise ValueError(
                f"No users.json or groups.json found in {zip_path}. "
                f"Contents: {zf.namelist()}"
            )

        if users_file:
            raw = json.loads(zf.read(users_file))
            result["users"] = raw.get("data", [])

        if groups_file:
            raw = json.loads(zf.read(groups_file))
            result["groups"] = raw.get("data", [])

    return result


# ── ADUser node import ───────────────────────────────────────────────────────


def _extract_username(name: str) -> str:
    """Extract the username portion from a SharpHound principal name.

    SharpHound names are typically "USERNAME@DOMAIN.COM".
    Returns the part before '@', or the full name if no '@' is present.
    """
    if "@" in name:
        return name.split("@")[0]
    return name


def import_ad_users(session, users_data: list[dict]) -> int:
    """Create ADUser nodes from SharpHound user data.

    Each ADUser node has properties:
      - object_id: The SID (Security Identifier)
      - name: The full principal name (e.g. JOHN.DOE@CONTOSO.COM)
      - domain: The AD domain
      - enabled: Whether the account is enabled
      - admin_count: Whether the user has adminCount set

    Uses batched UNWIND for efficient bulk import instead of per-user queries.

    Args:
        session: Neo4j session.
        users_data: List of user dicts from SharpHound users.json.

    Returns:
        Number of ADUser nodes created/updated.
    """
    batch = []
    for user in users_data:
        props = user.get("Properties", {})
        object_id = props.get("objectid", "")
        name = props.get("name", "")
        domain = props.get("domain", "")
        enabled = props.get("enabled", False)
        admin_count = props.get("admincount", False)

        if not object_id:
            continue

        batch.append(
            {
                "object_id": object_id,
                "name": name,
                "domain": domain,
                "enabled": enabled,
                "admin_count": admin_count,
                "username": _extract_username(name),
            }
        )

    if not batch:
        return 0

    result = session.run(
        """
        UNWIND $batch AS row
        MERGE (u:ADUser {object_id: row.object_id})
        SET u.name = row.name,
            u.domain = row.domain,
            u.enabled = row.enabled,
            u.admin_count = row.admin_count,
            u.username = row.username
        RETURN count(u) AS n
        """,
        batch=batch,
    )
    return result.single()["n"]


# ── SAME_IDENTITY edge creation ──────────────────────────────────────────────


def import_same_identity_edges(session) -> int:
    """Create SAME_IDENTITY edges between ADUser and User nodes.

    Matches by case-insensitive comparison of the ADUser's extracted username
    against the Rootstock User node's name. This enables cross-domain queries
    linking AD principals to macOS local users.

    Args:
        session: Neo4j session.

    Returns:
        Number of SAME_IDENTITY edges created.
    """
    result = session.run(
        """
        MATCH (ad:ADUser), (u:User)
        WHERE toLower(ad.username) = toLower(u.name)
        MERGE (ad)-[r:SAME_IDENTITY]->(u)
        RETURN count(r) AS n
        """
    )
    return result.single()["n"]


# ── AD_MEMBER_OF edge creation ───────────────────────────────────────────────


def import_ad_groups(session, groups_data: list[dict]) -> int:
    """Create ADGroup nodes from SharpHound group data.

    Args:
        session: Neo4j session.
        groups_data: List of group dicts from SharpHound groups.json.

    Returns:
        Number of ADGroup nodes created/updated.
    """
    batch = []
    for group in groups_data:
        props = group.get("Properties", {})
        object_id = props.get("objectid", "")
        name = props.get("name", "")
        domain = props.get("domain", "")

        if not object_id or not name:
            continue

        batch.append({
            "object_id": object_id,
            "name": name,
            "domain": domain,
        })

    if not batch:
        return 0

    result = session.run(
        """
        UNWIND $batch AS row
        MERGE (g:ADGroup {object_id: row.object_id})
        SET g.name = row.name,
            g.domain = row.domain
        RETURN count(g) AS n
        """,
        batch=batch,
    )
    return result.single()["n"]


def import_ad_member_of_edges(session, groups_data: list[dict]) -> int:
    """Create AD_MEMBER_OF edges from ADUser to ADGroup.

    Processes the Members array from each SharpHound group entry, creating
    edges for User-type members that exist as ADUser nodes in the graph.

    Args:
        session: Neo4j session.
        groups_data: List of group dicts from SharpHound groups.json.

    Returns:
        Number of AD_MEMBER_OF edges created.
    """
    batch = []
    for group in groups_data:
        props = group.get("Properties", {})
        group_object_id = props.get("objectid", "")
        members = group.get("Members", [])

        if not group_object_id:
            continue

        for member in members:
            member_type = member.get("ObjectType", "")
            member_sid = member.get("ObjectIdentifier", "")

            # Only link User-type members (skip Group, Computer, etc.)
            if member_type != "User" or not member_sid:
                continue

            batch.append({
                "member_sid": member_sid,
                "group_object_id": group_object_id,
            })

    if not batch:
        return 0

    result = session.run(
        """
        UNWIND $batch AS row
        MATCH (u:ADUser {object_id: row.member_sid})
        MATCH (g:ADGroup {object_id: row.group_object_id})
        MERGE (u)-[r:AD_MEMBER_OF]->(g)
        RETURN count(r) AS n
        """,
        batch=batch,
    )
    return result.single()["n"]


# ── Orchestrator ─────────────────────────────────────────────────────────────


def import_all(session, zip_path: str) -> dict[str, int]:
    """Orchestrate the full BloodHound import pipeline.

    Steps:
      1. Parse the SharpHound ZIP archive
      2. Import ADUser nodes
      3. Import ADGroup nodes (from groups.json)
      4. Create SAME_IDENTITY edges (ADUser -> User)
      5. Create AD_MEMBER_OF edges (ADUser -> ADGroup)

    Args:
        session: Neo4j session.
        zip_path: Path to the SharpHound ZIP file.

    Returns:
        Dict with counts for each import step.
    """
    data = parse_sharphound_zip(zip_path)

    ad_users = import_ad_users(session, data["users"])
    ad_groups = import_ad_groups(session, data["groups"])
    same_identity = import_same_identity_edges(session)
    member_of = import_ad_member_of_edges(session, data["groups"])

    return {
        "ad_users": ad_users,
        "ad_groups": ad_groups,
        "same_identity_edges": same_identity,
        "ad_member_of_edges": member_of,
    }


# ── CLI ──────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Import SharpHound ZIP data into Rootstock Neo4j graph"
    )
    add_neo4j_args(parser)
    parser.add_argument(
        "--zip", required=True, help="Path to SharpHound ZIP export file"
    )
    args = parser.parse_args()

    driver = connect_from_args(args)

    print(f"Importing SharpHound data from {args.zip}...")
    with driver.session() as session:
        counts = import_all(session, args.zip)

    driver.close()

    print(f"  ADUser nodes: {counts['ad_users']}")
    print(f"  ADGroup nodes: {counts['ad_groups']}")
    print(f"  SAME_IDENTITY edges: {counts['same_identity_edges']}")
    print(f"  AD_MEMBER_OF edges: {counts['ad_member_of_edges']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
