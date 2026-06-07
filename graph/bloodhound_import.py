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

EXPECTED_SHARPHOUND_FILES = ("users.json", "groups.json")
MAX_SHARPHOUND_JSON_SIZE = 100 * 1024 * 1024  # 100 MB per JSON file


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
        Dict with parsed user/group lists and import diagnostics.

    Raises:
        FileNotFoundError: If the ZIP file does not exist.
        zipfile.BadZipFile: If the file is not a valid ZIP archive.
        ValueError: If neither users.json nor groups.json is found.
    """
    zip_path_obj = Path(zip_path)
    if not zip_path_obj.exists():
        raise FileNotFoundError(f"ZIP file not found: {zip_path}")

    with zipfile.ZipFile(zip_path, "r") as zf:
        return _parse_sharphound_archive(zf, zip_path)


def _parse_sharphound_archive(zf: zipfile.ZipFile, zip_path: str) -> dict:
    users: list[dict] = []
    groups: list[dict] = []
    files_present: list[str] = []

    for info in zf.infolist():
        _validate_zip_entry(info)

    users_file = _find_json_in_zip(zf, "users.json")
    groups_file = _find_json_in_zip(zf, "groups.json")

    if not users_file and not groups_file:
        raise ValueError(
            f"No users.json or groups.json found in {zip_path}. "
            f"Contents: {zf.namelist()}"
        )

    if users_file:
        users = _read_sharphound_data(zf, users_file)
        files_present.append("users.json")

    if groups_file:
        groups = _read_sharphound_data(zf, groups_file)
        files_present.append("groups.json")

    files_missing = [
        expected for expected in EXPECTED_SHARPHOUND_FILES if expected not in files_present
    ]
    return {
        "users": users,
        "groups": groups,
        "diagnostics": {
            "files_present": files_present,
            "files_missing": files_missing,
            "parsed": {"users": len(users), "groups": len(groups)},
        },
    }


def _validate_zip_entry(info: zipfile.ZipInfo) -> None:
    if info.file_size > MAX_SHARPHOUND_JSON_SIZE:
        raise ValueError(
            f"Entry {info.filename} decompressed size "
            f"({info.file_size} bytes) exceeds limit"
        )
    if os.path.isabs(info.filename) or ".." in info.filename.split("/"):
        raise ValueError(f"Unsafe path in ZIP: {info.filename}")


def _read_sharphound_data(zf: zipfile.ZipFile, name: str) -> list[dict]:
    raw = json.loads(zf.read(name))
    return raw.get("data", [])


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
    batch = _ad_user_batch(users_data)
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


def _ad_user_batch(users_data: list[dict]) -> list[dict]:
    batch = []
    for user in users_data:
        row = _ad_user_row(user)
        if row is not None:
            batch.append(row)
    return batch


def _ad_user_row(user: dict) -> dict | None:
    props = user.get("Properties", {})
    object_id = props.get("objectid", "")
    if not object_id:
        return None
    name = props.get("name", "")
    return {
        "object_id": object_id,
        "name": name,
        "domain": props.get("domain", ""),
        "enabled": props.get("enabled", False),
        "admin_count": props.get("admincount", False),
        "username": _extract_username(name),
    }


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


def import_all(session, zip_path: str) -> dict:
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
        Dict with counts for each import step and import diagnostics.
    """
    data = parse_sharphound_zip(zip_path)

    ad_users = import_ad_users(session, data["users"])
    ad_groups = import_ad_groups(session, data["groups"])
    same_identity = import_same_identity_edges(session)
    member_of = import_ad_member_of_edges(session, data["groups"])
    diagnostics = _import_diagnostics(
        data,
        imported={
            "ad_users": ad_users,
            "ad_groups": ad_groups,
            "same_identity_edges": same_identity,
            "ad_member_of_edges": member_of,
        },
    )

    return {
        "ad_users": ad_users,
        "ad_groups": ad_groups,
        "same_identity_edges": same_identity,
        "ad_member_of_edges": member_of,
        "diagnostics": diagnostics,
    }


def _import_diagnostics(data: dict, *, imported: dict[str, int]) -> dict:
    diagnostics = dict(data.get("diagnostics", {}))
    skipped = _skipped_record_counts(data["users"], data["groups"])
    diagnostics["imported"] = imported
    diagnostics["skipped"] = skipped
    diagnostics["status"] = (
        "partial"
        if diagnostics.get("files_missing") or any(skipped.values())
        else "complete"
    )
    return diagnostics


def _skipped_record_counts(
    users_data: list[dict],
    groups_data: list[dict],
) -> dict[str, int]:
    skipped = _empty_skipped_record_counts()
    skipped["users.missing_objectid"] = _count_users_missing_objectid(users_data)
    skipped["groups.missing_objectid"] = _count_groups_missing_property(
        groups_data, "objectid"
    )
    skipped["groups.missing_name"] = _count_groups_missing_property(groups_data, "name")
    skipped["members.user_missing_objectid"] = _count_user_members_missing_objectid(
        groups_data
    )
    return skipped


def _empty_skipped_record_counts() -> dict[str, int]:
    return {
        "users.missing_objectid": 0,
        "groups.missing_objectid": 0,
        "groups.missing_name": 0,
        "members.user_missing_objectid": 0,
    }


def _count_users_missing_objectid(users_data: list[dict]) -> int:
    return sum(
        1 for user in users_data if not user.get("Properties", {}).get("objectid")
    )


def _count_groups_missing_property(groups_data: list[dict], property_name: str) -> int:
    return sum(
        1 for group in groups_data if not group.get("Properties", {}).get(property_name)
    )


def _count_user_members_missing_objectid(groups_data: list[dict]) -> int:
    return sum(
        1
        for group in groups_data
        for member in group.get("Members", [])
        if member.get("ObjectType") == "User" and not member.get("ObjectIdentifier")
    )


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
    _print_diagnostics(counts["diagnostics"])
    return 0


def _print_diagnostics(diagnostics: dict) -> None:
    print(f"  Import status: {diagnostics['status']}")
    parsed = diagnostics["parsed"]
    print(f"  Parsed records: users={parsed['users']}, groups={parsed['groups']}")
    missing = diagnostics["files_missing"]
    if missing:
        print(f"  Missing files: {', '.join(missing)}")
    skipped = {
        reason: count for reason, count in diagnostics["skipped"].items() if count
    }
    if skipped:
        formatted = ", ".join(f"{reason}={count}" for reason, count in sorted(skipped.items()))
        print(f"  Skipped records: {formatted}")


if __name__ == "__main__":
    sys.exit(main())
