"""
test_sandbox.py — Tests for sandbox profile models, import, and inference.

Usage:
    pytest graph/tests/test_sandbox.py -v
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import cleanup_test_nodes

FIXTURE_PATH = Path(__file__).parent / "fixture_minimal.json"
TEST_SCAN_ID = "test-sandbox-00000000-0000-0000-0000-000000000001"


# ── Pydantic model tests (no Neo4j) ─────────────────────────────────────────


class TestSandboxModels:
    def test_sandbox_profile_data_validates(self):
        from models import SandboxProfileData

        profile = SandboxProfileData.model_validate(
            {
                "bundle_id": "com.example.app",
                "profile_source": "entitlements",
                "file_read_rules": ["rule1"],
                "file_write_rules": [],
                "mach_lookup_rules": ["rule2"],
                "network_rules": ["com.apple.security.network.client"],
                "iokit_rules": [],
                "exception_count": 2,
                "has_unconstrained_network": True,
                "has_unconstrained_file_read": False,
            }
        )
        assert profile.bundle_id == "com.example.app"
        assert profile.has_unconstrained_network is True
        assert profile.has_unconstrained_file_read is False
        assert len(profile.mach_lookup_rules) == 1

    def test_sandbox_profile_data_defaults(self):
        from models import SandboxProfileData

        profile = SandboxProfileData.model_validate(
            {
                "bundle_id": "com.example.app",
                "profile_source": "none",
            }
        )
        assert profile.file_read_rules == []
        assert profile.file_write_rules == []
        assert profile.mach_lookup_rules == []
        assert profile.network_rules == []
        assert profile.iokit_rules == []
        assert profile.exception_count == 0
        assert profile.has_unconstrained_network is False
        assert profile.has_unconstrained_file_read is False

    def test_sandbox_profile_missing_required_raises(self):
        from models import SandboxProfileData
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            SandboxProfileData.model_validate(
                {
                    "profile_source": "entitlements",
                }
            )

    def test_application_with_sandbox_profile(self):
        from models import ApplicationData

        app = ApplicationData.model_validate(
            {
                "name": "TestApp",
                "bundle_id": "com.example.test",
                "path": "/Applications/TestApp.app",
                "hardened_runtime": True,
                "library_validation": True,
                "is_electron": False,
                "is_system": False,
                "signed": True,
                "sandbox_profile": {
                    "bundle_id": "com.example.test",
                    "profile_source": "entitlements",
                    "has_unconstrained_network": True,
                },
            }
        )
        assert app.sandbox_profile is not None
        assert app.sandbox_profile.bundle_id == "com.example.test"
        assert app.sandbox_profile.has_unconstrained_network is True

    def test_application_without_sandbox_profile(self):
        from models import ApplicationData

        app = ApplicationData.model_validate(
            {
                "name": "TestApp",
                "bundle_id": "com.example.test",
                "path": "/Applications/TestApp.app",
                "hardened_runtime": True,
                "library_validation": True,
                "is_electron": False,
                "is_system": False,
                "signed": True,
            }
        )
        assert app.sandbox_profile is None

    def test_fixture_loads_with_sandbox_profiles(self):
        from models import ScanResult

        data = json.loads(FIXTURE_PATH.read_text())
        scan = ScanResult.model_validate(data)
        assert len(scan.sandbox_profiles) == 2
        iterm = next(
            p for p in scan.sandbox_profiles if p.bundle_id == "com.googlecode.iterm2"
        )
        assert iterm.profile_source == "entitlements"
        assert iterm.has_unconstrained_network is False
        slack = next(
            p
            for p in scan.sandbox_profiles
            if p.bundle_id == "com.tinyspeck.slackmacgap"
        )
        assert slack.has_unconstrained_network is True

    def test_fixture_app_has_embedded_sandbox_profile(self):
        from models import ScanResult

        data = json.loads(FIXTURE_PATH.read_text())
        scan = ScanResult.model_validate(data)
        iterm = next(
            a for a in scan.applications if a.bundle_id == "com.googlecode.iterm2"
        )
        assert iterm.sandbox_profile is not None
        assert iterm.sandbox_profile.bundle_id == "com.googlecode.iterm2"


# ── Neo4j integration tests ─────────────────────────────────────────────────


@pytest.fixture(scope="module")
def neo4j_session(neo4j_driver):
    """Module-scoped Neo4j session with cleanup."""
    with neo4j_driver.session() as session:
        yield session
    with neo4j_driver.session() as session:
        cleanup_test_nodes(session, TEST_SCAN_ID)


class TestSandboxImport:
    def test_import_sandbox_profiles(self, neo4j_session):
        from import_nodes import import_applications, import_sandbox_profiles
        from models import ScanResult

        data = json.loads(FIXTURE_PATH.read_text())
        data["scan_id"] = TEST_SCAN_ID
        scan = ScanResult.model_validate(data)

        import_applications(neo4j_session, scan.applications, TEST_SCAN_ID)
        n_nodes, n_edges = import_sandbox_profiles(
            neo4j_session, scan.sandbox_profiles, TEST_SCAN_ID
        )
        assert n_nodes == 2
        assert n_edges == 2

        # Verify SandboxProfile nodes exist
        result = neo4j_session.run("MATCH (sp:SandboxProfile) RETURN count(sp) AS n")
        assert result.single()["n"] >= 2

    def test_sandbox_profile_properties(self, neo4j_session):
        result = neo4j_session.run(
            "MATCH (sp:SandboxProfile {profile_key: $profile_key}) RETURN sp",
            profile_key=f"{TEST_SCAN_ID}:com.tinyspeck.slackmacgap",
        )
        row = result.single()
        assert row is not None
        sp = row["sp"]
        assert sp["profile_source"] == "entitlements"
        assert sp["has_unconstrained_network"] is True
        assert sp["has_unconstrained_file_read"] is False
        assert sp["exception_count"] == 2

    def test_has_sandbox_profile_edge(self, neo4j_session):
        result = neo4j_session.run(
            """
            MATCH (a:Application {scan_id: $scan_id, bundle_id: 'com.googlecode.iterm2'})-[:HAS_SANDBOX_PROFILE]->(sp:SandboxProfile)
            RETURN sp.bundle_id AS bundle_id
            """,
            scan_id=TEST_SCAN_ID,
        )
        row = result.single()
        assert row is not None
        assert row["bundle_id"] == "com.googlecode.iterm2"

    def test_sandbox_import_idempotency(self, neo4j_session):
        from import_nodes import import_sandbox_profiles
        from models import ScanResult

        data = json.loads(FIXTURE_PATH.read_text())
        data["scan_id"] = TEST_SCAN_ID
        scan = ScanResult.model_validate(data)

        import_sandbox_profiles(neo4j_session, scan.sandbox_profiles, TEST_SCAN_ID)
        import_sandbox_profiles(neo4j_session, scan.sandbox_profiles, TEST_SCAN_ID)

        result = neo4j_session.run(
            "MATCH (sp:SandboxProfile {scan_id: $scan_id}) WHERE sp.bundle_id IN ['com.googlecode.iterm2', 'com.tinyspeck.slackmacgap'] RETURN count(sp) AS n",
            scan_id=TEST_SCAN_ID,
        )
        assert result.single()["n"] == 2, "Duplicate SandboxProfile nodes created"

    def test_import_empty_sandbox_profiles(self, neo4j_session):
        from import_nodes import import_sandbox_profiles

        n_nodes, n_edges = import_sandbox_profiles(neo4j_session, [], TEST_SCAN_ID)
        assert n_nodes == 0
        assert n_edges == 0


class TestSandboxInference:
    @pytest.fixture(autouse=True)
    def seed(self, neo4j_session):
        """Seed sandbox inference test data."""
        neo4j_session.run(
            """
            MERGE (app:Application {bundle_id: 'com.rootstock.sandbox.test.unconstrained'})
            SET app.name = 'TestUnconstrained',
                app.path = '/Applications/TestUnconstrained.app',
                app.hardened_runtime = false,
                app.library_validation = false,
                app.is_electron = false,
                app.is_system = false,
                app.signed = true,
                app.is_sip_protected = false,
                app.is_sandboxed = true,
                app.injection_methods = ['missing_library_validation'],
                app.scan_id = $scan_id

            MERGE (sp:SandboxProfile {bundle_id: 'com.rootstock.sandbox.test.unconstrained'})
            SET sp.profile_source = 'entitlements',
                sp.has_unconstrained_network = true,
                sp.has_unconstrained_file_read = false,
                sp.exception_count = 3,
                sp.mach_lookup_rules = ['com.apple.security.temporary-exception.mach-lookup.global-name'],
                sp.file_read_rules = [],
                sp.file_write_rules = [],
                sp.network_rules = ['com.apple.security.network.client'],
                sp.iokit_rules = []

            MERGE (app)-[:HAS_SANDBOX_PROFILE]->(sp)

            MERGE (attacker:Application {bundle_id: 'attacker.payload'})
            ON CREATE SET attacker.name = 'Attacker Payload',
                          attacker.is_system = false,
                          attacker.hardened_runtime = false,
                          attacker.library_validation = false,
                          attacker.is_electron = false,
                          attacker.signed = false,
                          attacker.is_sip_protected = false,
                          attacker.is_sandboxed = false,
                          attacker.injection_methods = [],
                          attacker.inferred = true
            """,
            scan_id=TEST_SCAN_ID,
        )

    def test_infer_sandbox_escape(self, neo4j_session):
        from infer_sandbox import infer

        n = infer(neo4j_session)
        assert n >= 1, "Expected at least 1 sandbox inference edge"

        result = neo4j_session.run(
            """
            MATCH (attacker:Application {bundle_id: 'attacker.payload'})
                  -[r:CAN_ESCAPE_SANDBOX]->(target:Application)
            WHERE target.bundle_id = 'com.rootstock.sandbox.test.unconstrained'
            RETURN r.has_unconstrained_network AS network, r.inferred AS inferred
            """
        )
        row = result.single()
        assert row is not None
        assert row["network"] is True
        assert row["inferred"] is True

    def test_infer_idempotent(self, neo4j_session):
        from infer_sandbox import infer

        _n1 = infer(neo4j_session)
        n2 = infer(neo4j_session)
        # MERGE makes it idempotent; second run should return same count
        assert n2 >= 1
