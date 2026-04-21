"""
test_bloodhound_import.py — Tests for BloodHound SharpHound ZIP import.

Pure unit tests for parsing and import logic — no Neo4j required for most tests.
Integration tests require a running Neo4j instance.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Ensure graph/ is on sys.path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from bloodhound_import import (
    _extract_username,
    import_ad_member_of_edges,
    import_ad_users,
    import_all,
    import_same_identity_edges,
    parse_sharphound_zip,
)


# ── Test data ────────────────────────────────────────────────────────────────

SAMPLE_USERS = {
    "data": [
        {
            "Properties": {
                "name": "JOHN.DOE@CONTOSO.COM",
                "domain": "CONTOSO.COM",
                "objectid": "S-1-5-21-1234567890-1234567890-1234567890-1001",
                "enabled": True,
                "admincount": False,
            },
            "PrimaryGroupSID": "S-1-5-21-1234567890-1234567890-1234567890-513",
        },
        {
            "Properties": {
                "name": "ADMIN.USER@CONTOSO.COM",
                "domain": "CONTOSO.COM",
                "objectid": "S-1-5-21-1234567890-1234567890-1234567890-500",
                "enabled": True,
                "admincount": True,
            },
            "PrimaryGroupSID": "S-1-5-21-1234567890-1234567890-1234567890-513",
        },
        {
            "Properties": {
                "name": "DISABLED.USER@CONTOSO.COM",
                "domain": "CONTOSO.COM",
                "objectid": "S-1-5-21-1234567890-1234567890-1234567890-1099",
                "enabled": False,
                "admincount": False,
            },
            "PrimaryGroupSID": "S-1-5-21-1234567890-1234567890-1234567890-513",
        },
    ]
}

SAMPLE_GROUPS = {
    "data": [
        {
            "Properties": {
                "name": "DOMAIN ADMINS@CONTOSO.COM",
                "domain": "CONTOSO.COM",
                "objectid": "S-1-5-21-1234567890-1234567890-1234567890-512",
            },
            "Members": [
                {
                    "ObjectIdentifier": "S-1-5-21-1234567890-1234567890-1234567890-500",
                    "ObjectType": "User",
                },
            ],
        },
        {
            "Properties": {
                "name": "DOMAIN USERS@CONTOSO.COM",
                "domain": "CONTOSO.COM",
                "objectid": "S-1-5-21-1234567890-1234567890-1234567890-513",
            },
            "Members": [
                {
                    "ObjectIdentifier": "S-1-5-21-1234567890-1234567890-1234567890-1001",
                    "ObjectType": "User",
                },
                {
                    "ObjectIdentifier": "S-1-5-21-1234567890-1234567890-1234567890-500",
                    "ObjectType": "User",
                },
                {
                    "ObjectIdentifier": "S-1-5-21-1234567890-1234567890-1234567890-1099",
                    "ObjectType": "User",
                },
                {
                    "ObjectIdentifier": "S-1-5-21-1234567890-1234567890-1234567890-512",
                    "ObjectType": "Group",
                },
            ],
        },
    ]
}


def _create_test_zip(tmpdir: str, users=True, groups=True) -> str:
    """Create a SharpHound-style ZIP archive in tmpdir."""
    zip_path = os.path.join(tmpdir, "sharphound_test.zip")
    with zipfile.ZipFile(zip_path, "w") as zf:
        if users:
            zf.writestr("users.json", json.dumps(SAMPLE_USERS))
        if groups:
            zf.writestr("groups.json", json.dumps(SAMPLE_GROUPS))
    return zip_path


# ── Unit tests: ZIP parsing ──────────────────────────────────────────────────


class TestParseSharpHoundZip:
    def test_parse_full_zip(self):
        """Parse a ZIP containing both users.json and groups.json."""
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = _create_test_zip(tmpdir)
            result = parse_sharphound_zip(zip_path)

        assert "users" in result
        assert "groups" in result
        assert len(result["users"]) == 3
        assert len(result["groups"]) == 2

    def test_parse_users_only_zip(self):
        """Parse a ZIP with only users.json."""
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = _create_test_zip(tmpdir, users=True, groups=False)
            result = parse_sharphound_zip(zip_path)

        assert len(result["users"]) == 3
        assert len(result["groups"]) == 0

    def test_parse_groups_only_zip(self):
        """Parse a ZIP with only groups.json."""
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = _create_test_zip(tmpdir, users=False, groups=True)
            result = parse_sharphound_zip(zip_path)

        assert len(result["users"]) == 0
        assert len(result["groups"]) == 2

    def test_parse_empty_zip_raises(self):
        """ZIP without users.json or groups.json should raise ValueError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = os.path.join(tmpdir, "empty.zip")
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("readme.txt", "nothing here")
            with pytest.raises(ValueError, match="No users.json or groups.json"):
                parse_sharphound_zip(zip_path)

    def test_parse_missing_zip_raises(self):
        """Non-existent ZIP should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            parse_sharphound_zip("/nonexistent/path/test.zip")

    def test_user_properties_extracted(self):
        """Verify user properties are properly extracted from the data list."""
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = _create_test_zip(tmpdir)
            result = parse_sharphound_zip(zip_path)

        user = result["users"][0]
        props = user["Properties"]
        assert props["name"] == "JOHN.DOE@CONTOSO.COM"
        assert props["objectid"].startswith("S-1-5-21-")
        assert props["enabled"] is True

    def test_group_members_extracted(self):
        """Verify group members are properly extracted from the data list."""
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = _create_test_zip(tmpdir)
            result = parse_sharphound_zip(zip_path)

        domain_admins = result["groups"][0]
        assert domain_admins["Properties"]["name"] == "DOMAIN ADMINS@CONTOSO.COM"
        assert len(domain_admins["Members"]) == 1
        assert domain_admins["Members"][0]["ObjectType"] == "User"


# ── Unit tests: username extraction ──────────────────────────────────────────


class TestExtractUsername:
    def test_standard_upn(self):
        assert _extract_username("JOHN.DOE@CONTOSO.COM") == "JOHN.DOE"

    def test_no_at_sign(self):
        assert _extract_username("johndoe") == "johndoe"

    def test_empty_string(self):
        assert _extract_username("") == ""

    def test_multiple_at_signs(self):
        assert _extract_username("user@sub@domain.com") == "user"


# ── Unit tests: import functions with mock session ───────────────────────────


class TestImportADUsers:
    def test_imports_valid_users(self):
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.single.return_value = {"n": 3}
        mock_session.run.return_value = mock_result

        count = import_ad_users(mock_session, SAMPLE_USERS["data"])
        assert count == 3
        # Batched UNWIND: single session.run call for all users
        assert mock_session.run.call_count == 1

    def test_skips_users_without_objectid(self):
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.single.return_value = {"n": 1}
        mock_session.run.return_value = mock_result

        data = [{"Properties": {"name": "NO_SID@CONTOSO.COM", "objectid": ""}}]
        count = import_ad_users(mock_session, data)
        assert count == 0
        assert mock_session.run.call_count == 0

    def test_merge_cypher_contains_ad_user(self):
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.single.return_value = {"n": 1}
        mock_session.run.return_value = mock_result

        import_ad_users(mock_session, [SAMPLE_USERS["data"][0]])
        call_args = mock_session.run.call_args
        assert "MERGE" in call_args[0][0]
        assert "ADUser" in call_args[0][0]


class TestImportSameIdentityEdges:
    def test_creates_same_identity_edges(self):
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.single.return_value = {"n": 2}
        mock_session.run.return_value = mock_result

        count = import_same_identity_edges(mock_session)
        assert count == 2

    def test_cypher_uses_case_insensitive_match(self):
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.single.return_value = {"n": 0}
        mock_session.run.return_value = mock_result

        import_same_identity_edges(mock_session)
        call_args = mock_session.run.call_args
        cypher = call_args[0][0]
        assert "toLower" in cypher
        assert "SAME_IDENTITY" in cypher


class TestImportADMemberOfEdges:
    def test_creates_member_of_edges_for_users_only(self):
        mock_session = MagicMock()
        mock_result = MagicMock()
        # The batched UNWIND creates all edges in a single call
        mock_result.single.return_value = {"n": 4}
        mock_session.run.return_value = mock_result

        count = import_ad_member_of_edges(mock_session, SAMPLE_GROUPS["data"])
        # Domain Admins has 1 User member
        # Domain Users has 3 User members + 1 Group member (skipped)
        # Total: 4 User members in the batch
        assert count == 4
        # Verify single batched call with UNWIND
        assert mock_session.run.call_count == 1
        call_args = mock_session.run.call_args
        assert "UNWIND" in call_args[0][0]

    def test_skips_non_user_members(self):
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.single.return_value = {"n": 0}
        mock_session.run.return_value = mock_result

        groups = [
            {
                "Properties": {"name": "TEST@CONTOSO.COM", "objectid": "S-1-5-test"},
                "Members": [
                    {"ObjectIdentifier": "S-1-5-computer", "ObjectType": "Computer"},
                    {"ObjectIdentifier": "S-1-5-group", "ObjectType": "Group"},
                ],
            }
        ]
        count = import_ad_member_of_edges(mock_session, groups)
        assert count == 0
        # No User members → empty batch → no session.run call
        assert mock_session.run.call_count == 0


class TestImportAll:
    def test_returns_dict_with_expected_keys(self):
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.single.return_value = {"n": 0}
        mock_session.run.return_value = mock_result

        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = _create_test_zip(tmpdir)
            counts = import_all(mock_session, zip_path)

        assert "ad_users" in counts
        assert "ad_groups" in counts
        assert "same_identity_edges" in counts
        assert "ad_member_of_edges" in counts


# ── Integration tests (require Neo4j) ────────────────────────────────────────


class TestBloodHoundImportIntegration:
    @pytest.fixture(autouse=True)
    def setup_and_teardown(self, neo4j_driver):
        self.driver = neo4j_driver
        yield
        # Clean up ADUser and test User nodes
        with self.driver.session() as session:
            session.run("MATCH (n:ADUser) DETACH DELETE n")
            session.run(
                "MATCH (u:User) WHERE u.name IN ['john.doe', 'admin.user'] "
                "DETACH DELETE u"
            )
            session.run(
                "MATCH (g:ADGroup) WHERE g.name CONTAINS 'CONTOSO' DETACH DELETE g"
            )

    def test_full_import_creates_ad_users(self):
        """End-to-end: import creates ADUser nodes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = _create_test_zip(tmpdir)
            with self.driver.session() as session:
                counts = import_all(session, zip_path)

        assert counts["ad_users"] == 3

        with self.driver.session() as session:
            result = session.run("MATCH (u:ADUser) RETURN count(u) AS n")
            assert result.single()["n"] == 3

    def test_same_identity_edge_created(self):
        """SAME_IDENTITY edges are created when matching User nodes exist."""
        with self.driver.session() as session:
            # Create a Rootstock User node that matches an AD user
            session.run("MERGE (u:User {name: 'john.doe'}) SET u.uid = 501")

        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = _create_test_zip(tmpdir)
            with self.driver.session() as session:
                counts = import_all(session, zip_path)

        assert counts["same_identity_edges"] >= 1

        with self.driver.session() as session:
            result = session.run(
                "MATCH (ad:ADUser)-[:SAME_IDENTITY]->(u:User) "
                "RETURN ad.name AS ad_name, u.name AS local_name"
            )
            row = result.single()
            assert row is not None
            assert row["local_name"] == "john.doe"

    def test_ad_member_of_edges_created(self):
        """AD_MEMBER_OF edges link ADUser to ADGroup."""
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = _create_test_zip(tmpdir)
            with self.driver.session() as session:
                counts = import_all(session, zip_path)

        assert counts["ad_member_of_edges"] >= 1

        with self.driver.session() as session:
            result = session.run(
                "MATCH (u:ADUser)-[:AD_MEMBER_OF]->(g:ADGroup) RETURN count(*) AS n"
            )
            assert result.single()["n"] >= 1

    def test_import_is_idempotent(self):
        """Running import twice should not create duplicate nodes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = _create_test_zip(tmpdir)
            with self.driver.session() as session:
                import_all(session, zip_path)
                count1 = session.run("MATCH (u:ADUser) RETURN count(u) AS n").single()[
                    "n"
                ]

                import_all(session, zip_path)
                count2 = session.run("MATCH (u:ADUser) RETURN count(u) AS n").single()[
                    "n"
                ]

        assert count1 == count2
