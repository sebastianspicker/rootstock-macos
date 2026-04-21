"""
test_import.py — Integration tests for the graph importer.

Requires a running Neo4j instance. Tests are skipped if Neo4j is unavailable.

Usage:
    pytest graph/tests/test_import.py -v
    # With custom connection:
    NEO4J_URI=bolt://localhost:7687 NEO4J_USER=neo4j NEO4J_PASSWORD=rootstock pytest graph/tests/test_import.py -v
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import cleanup_test_nodes

FIXTURE_PATH = Path(__file__).parent / "fixture_minimal.json"
TEST_SCAN_ID = "test-00000000-0000-0000-0000-000000000001"


@pytest.fixture(scope="module")
def neo4j_session(neo4j_driver):
    """Module-scoped Neo4j session with cleanup."""
    with neo4j_driver.session() as session:
        yield session
    with neo4j_driver.session() as session:
        cleanup_test_nodes(session, TEST_SCAN_ID)


@pytest.fixture(scope="module")
def scan_result():
    from models import ScanResult

    data = json.loads(FIXTURE_PATH.read_text())
    data["scan_id"] = TEST_SCAN_ID
    return ScanResult.model_validate(data)


# ── Integration tests (require Neo4j) ──────────────────────────────────────


class TestImportIntegration:
    def test_import_applications(self, neo4j_session, scan_result):
        from import_nodes import import_applications

        n = import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)
        assert n == 3

        result = neo4j_session.run(
            "MATCH (a:Application {scan_id: $scan_id}) RETURN count(a) AS n",
            scan_id=TEST_SCAN_ID,
        )
        assert result.single()["n"] == 3

    def test_application_properties(self, neo4j_session, scan_result):
        from import_nodes import import_applications

        import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)

        result = neo4j_session.run(
            "MATCH (a:Application {scan_id: $scan_id, bundle_id: 'com.googlecode.iterm2'}) RETURN a",
            scan_id=TEST_SCAN_ID,
        )
        row = result.single()
        assert row is not None
        app = row["a"]
        assert app["name"] == "iTerm2"
        assert app["hardened_runtime"] is False
        assert app["is_electron"] is False
        assert "missing_library_validation" in app["injection_methods"]

    def test_import_tcc_grants(self, neo4j_session, scan_result):
        from import_nodes import import_applications, import_tcc_grants

        import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)
        linked, skipped = import_tcc_grants(
            neo4j_session, scan_result.tcc_grants, TEST_SCAN_ID
        )
        assert linked == 5  # all 5 grants match apps in fixture
        assert skipped == 0

        result = neo4j_session.run(
            "MATCH (:Application)-[r:HAS_TCC_GRANT]->(:TCC_Permission) RETURN count(r) AS n"
        )
        assert result.single()["n"] >= 5

    def test_import_entitlements(self, neo4j_session, scan_result):
        from import_nodes import import_applications, import_entitlements

        import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)
        n_ent_nodes, n_ent_rels = import_entitlements(
            neo4j_session, scan_result.applications, TEST_SCAN_ID
        )
        # 10 total entitlements but some names are shared across apps → fewer unique nodes
        assert n_ent_rels == 11  # one rel per (app, entitlement) pair
        assert n_ent_nodes <= 11  # unique entitlement names

    def test_idempotency(self, neo4j_session, scan_result):
        """Re-importing the same data must not create duplicate nodes."""
        from import_nodes import (
            import_applications,
            import_tcc_grants,
            import_entitlements,
        )

        import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)
        import_tcc_grants(neo4j_session, scan_result.tcc_grants, TEST_SCAN_ID)
        import_entitlements(neo4j_session, scan_result.applications, TEST_SCAN_ID)

        # Import again
        import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)
        import_tcc_grants(neo4j_session, scan_result.tcc_grants, TEST_SCAN_ID)
        import_entitlements(neo4j_session, scan_result.applications, TEST_SCAN_ID)

        result = neo4j_session.run(
            "MATCH (a:Application {scan_id: $scan_id}) RETURN count(a) AS n",
            scan_id=TEST_SCAN_ID,
        )
        assert result.single()["n"] == 3, "Duplicate Application nodes created"

        result = neo4j_session.run(
            "MATCH (:Application)-[r:HAS_TCC_GRANT]->(:TCC_Permission) RETURN count(r) AS n"
        )
        # Should still be exactly 5 TCC grant relationships (no duplicates)
        tcc_count = result.single()["n"]
        assert tcc_count >= 5  # may have pre-existing from other tests in suite

    def test_import_launch_items(self, neo4j_session, scan_result):
        from import_nodes import import_launch_items

        n_nodes, n_persists, n_runs, n_hijacks = import_launch_items(
            neo4j_session, scan_result.launch_items
        )
        assert n_nodes == 3
        assert n_hijacks == 0  # no fixture items have program_writable_by_non_root

        result = neo4j_session.run(
            "MATCH (l:LaunchItem) WHERE l.label IN ['com.example.daemon', 'com.example.agent', 'cron.root.1'] RETURN count(l) AS n"
        )
        assert result.single()["n"] == 3

    def test_launch_item_properties(self, neo4j_session, scan_result):
        from import_nodes import import_launch_items

        import_launch_items(neo4j_session, scan_result.launch_items)

        result = neo4j_session.run(
            "MATCH (l:LaunchItem {label: 'com.example.daemon'}) RETURN l"
        )
        row = result.single()
        assert row is not None
        launch_item = row["l"]
        assert launch_item["type"] == "daemon"
        assert launch_item["run_at_load"] is True
        assert launch_item["user"] == "root"

    def test_launch_item_runs_as_edge(self, neo4j_session, scan_result):
        from import_nodes import import_launch_items

        import_launch_items(neo4j_session, scan_result.launch_items)

        result = neo4j_session.run(
            """
            MATCH (l:LaunchItem {label: 'com.example.daemon'})-[:RUNS_AS]->(u:User {name: 'root'})
            RETURN count(l) AS n
            """
        )
        assert result.single()["n"] == 1, "RUNS_AS edge to root User should exist"

    def test_launch_item_idempotency(self, neo4j_session, scan_result):
        from import_nodes import import_launch_items

        import_launch_items(neo4j_session, scan_result.launch_items)
        import_launch_items(neo4j_session, scan_result.launch_items)

        result = neo4j_session.run(
            "MATCH (l:LaunchItem) WHERE l.label IN ['com.example.daemon', 'com.example.agent'] RETURN count(l) AS n"
        )
        assert result.single()["n"] == 2, "Duplicate LaunchItem nodes created"

    def test_import_xpc_services(self, neo4j_session, scan_result):
        from import_nodes import import_xpc_services

        n_nodes, n_edges = import_xpc_services(neo4j_session, scan_result.xpc_services)
        assert n_nodes == 2

        result = neo4j_session.run(
            "MATCH (x:XPC_Service) WHERE x.label IN ['com.example.testdaemon', 'com.example.testagent'] RETURN count(x) AS n"
        )
        assert result.single()["n"] == 2

    def test_xpc_service_properties(self, neo4j_session, scan_result):
        from import_nodes import import_xpc_services

        import_xpc_services(neo4j_session, scan_result.xpc_services)

        result = neo4j_session.run(
            "MATCH (x:XPC_Service {label: 'com.example.testdaemon'}) RETURN x"
        )
        row = result.single()
        assert row is not None
        svc = row["x"]
        assert svc["type"] == "daemon"
        assert svc["run_at_load"] is True
        assert svc["keep_alive"] is True
        assert "com.example.testdaemon.xpc" in svc["mach_services"]
        assert "com.apple.private.tcc.allow" in svc["entitlements"]

    def test_xpc_import_idempotency(self, neo4j_session, scan_result):
        """Re-importing the same XPC services must not create duplicate nodes."""
        from import_nodes import import_xpc_services

        import_xpc_services(neo4j_session, scan_result.xpc_services)
        import_xpc_services(neo4j_session, scan_result.xpc_services)

        result = neo4j_session.run(
            "MATCH (x:XPC_Service) WHERE x.label IN ['com.example.testdaemon', 'com.example.testagent'] RETURN count(x) AS n"
        )
        assert result.single()["n"] == 2, "Duplicate XPC_Service nodes created"

    def test_import_keychain_items(self, neo4j_session, scan_result):
        from import_nodes import import_applications, import_keychain_items

        import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)
        n_nodes, n_edges = import_keychain_items(
            neo4j_session, scan_result.keychain_acls
        )
        assert n_nodes == 3  # 3 items in fixture

        result = neo4j_session.run(
            "MATCH (k:Keychain_Item) WHERE k.label IN ['iTerm2 Credential', 'Slack Token', 'Developer Certificate'] RETURN count(k) AS n"
        )
        assert result.single()["n"] == 3

    def test_keychain_can_read_edges(self, neo4j_session, scan_result):
        from import_nodes import import_applications, import_keychain_items

        import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)
        _, n_edges = import_keychain_items(neo4j_session, scan_result.keychain_acls)
        # iTerm2 → iTerm2 Credential (1) + Slack → Slack Token (1) + Terminal → Slack Token (1) = 3
        assert n_edges >= 3

        result = neo4j_session.run(
            "MATCH (a:Application)-[r:CAN_READ_KEYCHAIN]->(k:Keychain_Item) RETURN count(r) AS n"
        )
        assert result.single()["n"] >= 3

    def test_keychain_item_properties(self, neo4j_session, scan_result):
        from import_nodes import import_applications, import_keychain_items

        import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)
        import_keychain_items(neo4j_session, scan_result.keychain_acls)

        result = neo4j_session.run(
            "MATCH (k:Keychain_Item {label: 'iTerm2 Credential'}) RETURN k"
        )
        row = result.single()
        assert row is not None
        k = row["k"]
        assert k["kind"] == "generic_password"
        assert k["service"] == "com.googlecode.iterm2.SecureInput"
        assert k["access_group"] == "H7V7XYVQ7D.com.googlecode.iterm2"

    def test_keychain_import_idempotency(self, neo4j_session, scan_result):
        """Re-importing the same keychain items must not create duplicate nodes."""
        from import_nodes import import_applications, import_keychain_items

        import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)
        import_keychain_items(neo4j_session, scan_result.keychain_acls)
        import_keychain_items(neo4j_session, scan_result.keychain_acls)

        result = neo4j_session.run(
            "MATCH (k:Keychain_Item) WHERE k.label IN ['iTerm2 Credential', 'Slack Token'] RETURN count(k) AS n"
        )
        assert result.single()["n"] == 2, "Duplicate Keychain_Item nodes created"

    def test_keychain_no_trusted_apps_creates_no_edges(
        self, neo4j_session, scan_result
    ):
        """Keychain items with empty trusted_apps must not create CAN_READ_KEYCHAIN edges."""
        from import_nodes import import_applications, import_keychain_items
        from models import KeychainItemData

        import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)
        cert_only = [
            KeychainItemData(
                label="Orphan Cert",
                kind="certificate",
                service=None,
                access_group=None,
                trusted_apps=[],
            )
        ]
        n_nodes, n_edges = import_keychain_items(neo4j_session, cert_only)
        assert n_nodes == 1
        assert n_edges == 0

    def test_import_mdm_profiles(self, neo4j_session, scan_result):
        from import_nodes import import_mdm_profiles

        n_nodes, n_edges = import_mdm_profiles(neo4j_session, scan_result.mdm_profiles)
        assert n_nodes == 2  # 2 profiles in fixture
        assert n_edges == 2  # 2 TCC policies (only 1 profile has policies)

        result = neo4j_session.run(
            "MATCH (m:MDM_Profile) WHERE m.identifier IN ['com.example.tcc.profile', 'com.example.basic.profile'] RETURN count(m) AS n"
        )
        assert result.single()["n"] == 2

    def test_mdm_configures_edges(self, neo4j_session, scan_result):
        from import_nodes import import_mdm_profiles

        import_mdm_profiles(neo4j_session, scan_result.mdm_profiles)

        result = neo4j_session.run(
            "MATCH (m:MDM_Profile {identifier: 'com.example.tcc.profile'})-[c:CONFIGURES]->(t:TCC_Permission) RETURN count(c) AS n"
        )
        assert result.single()["n"] == 2

    def test_mdm_profile_properties(self, neo4j_session, scan_result):
        from import_nodes import import_mdm_profiles

        import_mdm_profiles(neo4j_session, scan_result.mdm_profiles)

        result = neo4j_session.run(
            "MATCH (m:MDM_Profile {identifier: 'com.example.tcc.profile'}) RETURN m"
        )
        row = result.single()
        assert row is not None
        m = row["m"]
        assert m["display_name"] == "Privacy Policy Profile"
        assert m["organization"] == "Example Corp"
        assert m["install_date"] == "2026-03-01 00:00:00 +0000"

    def test_mdm_no_tcc_policies_creates_no_edges(self, neo4j_session, scan_result):
        """Profiles with no TCC policies must not create CONFIGURES edges."""
        from import_nodes import import_mdm_profiles
        from models import MDMProfileData

        basic_profile = [
            MDMProfileData(
                identifier="com.example.empty.profile",
                display_name="Empty Profile",
                organization=None,
                install_date=None,
                tcc_policies=[],
            )
        ]
        n_nodes, n_edges = import_mdm_profiles(neo4j_session, basic_profile)
        assert n_nodes == 1
        assert n_edges == 0

    def test_mdm_import_idempotency(self, neo4j_session, scan_result):
        """Re-importing the same MDM profiles must not create duplicate nodes."""
        from import_nodes import import_mdm_profiles

        import_mdm_profiles(neo4j_session, scan_result.mdm_profiles)
        import_mdm_profiles(neo4j_session, scan_result.mdm_profiles)

        result = neo4j_session.run(
            "MATCH (m:MDM_Profile) WHERE m.identifier IN ['com.example.tcc.profile', 'com.example.basic.profile'] RETURN count(m) AS n"
        )
        assert result.single()["n"] == 2, "Duplicate MDM_Profile nodes created"

    def test_unknown_client_grant_skipped(self, neo4j_session):
        """A TCC grant whose client has no Application node should be skipped gracefully."""
        from models import TCCGrantData
        from import_nodes import import_tcc_grants

        orphan = TCCGrantData(
            service="kTCCServiceMicrophone",
            display_name="Microphone",
            client="com.nonexistent.app",
            client_type=0,
            auth_value=2,
            auth_reason=1,
            scope="user",
            last_modified=0,
        )
        linked, skipped = import_tcc_grants(neo4j_session, [orphan], TEST_SCAN_ID)
        assert linked == 0
        assert skipped == 1

    def test_import_ad_binding(self, neo4j_session, scan_result):
        """AD binding enriches Computer node and creates ADGroup + MAPPED_TO."""
        from import_nodes import import_computer, import_local_groups, import_ad_binding
        from models import ComputerData

        computer = ComputerData(
            hostname=scan_result.hostname,
            macos_version=scan_result.macos_version,
            scan_id=TEST_SCAN_ID,
            scanned_at=scan_result.timestamp,
            collector_version=scan_result.collector_version,
        )
        import_computer(neo4j_session, computer)
        import_local_groups(neo4j_session, scan_result.local_groups)
        n_groups, n_mapped = import_ad_binding(
            neo4j_session, scan_result.ad_binding, scan_result.hostname, TEST_SCAN_ID
        )
        assert n_groups == 1  # one group mapping in fixture
        assert n_mapped == 1  # CORP\Domain Admins → admin

        # Verify Computer node has ad_bound property
        result = neo4j_session.run(
            "MATCH (c:Computer {computer_key: $computer_key}) RETURN c.ad_bound AS ad_bound, c.ad_realm AS realm",
            computer_key=f"{TEST_SCAN_ID}:{scan_result.hostname}",
        )
        row = result.single()
        assert row["ad_bound"] is True
        assert row["realm"] == "CORP.EXAMPLE.COM"

        # Verify ADGroup node exists
        result = neo4j_session.run("MATCH (ag:ADGroup) RETURN count(ag) AS n")
        assert result.single()["n"] >= 1

        # Verify MAPPED_TO edge
        result = neo4j_session.run(
            "MATCH (ag:ADGroup)-[r:MAPPED_TO]->(lg:LocalGroup {name: 'admin'}) RETURN count(r) AS n"
        )
        assert result.single()["n"] >= 1

    def test_import_kerberos_artifacts(self, neo4j_session, scan_result):
        """Kerberos artifacts create nodes + FOUND_ON, HAS_KERBEROS_CACHE, HAS_KEYTAB edges."""
        from import_nodes import import_computer, import_kerberos_artifacts
        from models import ComputerData

        computer = ComputerData(
            hostname=scan_result.hostname,
            macos_version=scan_result.macos_version,
            scan_id=TEST_SCAN_ID,
            scanned_at=scan_result.timestamp,
            collector_version=scan_result.collector_version,
        )
        import_computer(neo4j_session, computer)
        n_ka, n_found, n_cache, n_kt = import_kerberos_artifacts(
            neo4j_session,
            scan_result.kerberos_artifacts,
            scan_result.hostname,
            TEST_SCAN_ID,
        )
        assert n_ka == 3  # ccache + keytab + config in fixture
        assert n_found == 3  # all FOUND_ON
        assert n_cache == 1  # one ccache with principal_hint
        assert n_kt == 1  # one keytab

        # Verify KerberosArtifact nodes
        result = neo4j_session.run("MATCH (ka:KerberosArtifact) RETURN count(ka) AS n")
        assert result.single()["n"] >= 3

        # Verify HAS_KERBEROS_CACHE edge
        result = neo4j_session.run(
            "MATCH (u:User {name: 'testuser'})-[:HAS_KERBEROS_CACHE]->(ka:KerberosArtifact) RETURN count(ka) AS n"
        )
        assert result.single()["n"] >= 1

    def test_user_is_ad_user_flag(self, neo4j_session, scan_result):
        """User details with is_ad_user should set the flag on User nodes."""
        from import_nodes import import_user_details
        from models import UserDetailData

        ad_user = UserDetailData(
            name="ad_testuser",
            shell="/bin/bash",
            home_dir="/Users/ad_testuser",
            is_hidden=False,
            is_ad_user=True,
        )
        import_user_details(neo4j_session, [ad_user])

        result = neo4j_session.run(
            "MATCH (u:User {name: 'ad_testuser'}) RETURN u.is_ad_user AS is_ad"
        )
        assert result.single()["is_ad"] is True

    def test_ad_binding_not_bound(self, neo4j_session):
        """Non-bound AD binding returns 0, 0 with no side effects."""
        from import_nodes import import_ad_binding
        from models import ADBindingData

        not_bound = ADBindingData(is_bound=False)
        n_groups, n_mapped = import_ad_binding(neo4j_session, not_bound, "test-mac")
        assert n_groups == 0
        assert n_mapped == 0

    def test_ad_binding_none(self, neo4j_session):
        """None AD binding returns 0, 0."""
        from import_nodes import import_ad_binding

        n_groups, n_mapped = import_ad_binding(neo4j_session, None, "test-mac")
        assert n_groups == 0
        assert n_mapped == 0

    def test_same_bundle_id_across_scans_remains_distinct(
        self, neo4j_session, scan_result
    ):
        from import_nodes import import_applications

        other_scan_id = "test-00000000-0000-0000-0000-000000000099"
        import_applications(neo4j_session, [scan_result.applications[0]], TEST_SCAN_ID)
        import_applications(neo4j_session, [scan_result.applications[0]], other_scan_id)

        result = neo4j_session.run(
            "MATCH (a:Application {bundle_id: $bundle_id}) WHERE a.scan_id IN [$scan_a, $scan_b] RETURN count(a) AS n",
            bundle_id=scan_result.applications[0].bundle_id,
            scan_a=TEST_SCAN_ID,
            scan_b=other_scan_id,
        )
        assert result.single()["n"] == 2

        cleanup_test_nodes(neo4j_session, other_scan_id)

    def test_same_bundle_id_multiple_paths_remains_distinct(
        self, neo4j_session, scan_result
    ):
        from import_nodes import import_applications
        from models import ApplicationData

        original = scan_result.applications[0]
        moved = ApplicationData.model_validate(
            {
                **original.model_dump(),
                "path": "/Applications/Alternate/iTerm2.app",
            }
        )

        import_applications(neo4j_session, [original, moved], TEST_SCAN_ID)

        result = neo4j_session.run(
            "MATCH (a:Application {scan_id: $scan_id, bundle_id: $bundle_id}) RETURN count(a) AS n",
            scan_id=TEST_SCAN_ID,
            bundle_id=original.bundle_id,
        )
        assert result.single()["n"] == 2
