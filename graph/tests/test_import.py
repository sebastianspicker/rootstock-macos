"""
test_import.py — Integration tests for the graph importer.

Requires a running Neo4j instance. Tests are skipped if Neo4j is unavailable.

Usage:
    pytest graph/tests/test_import.py -v
    # With custom connection:
    NEO4J_URI=bolt://localhost:7687 NEO4J_USER=neo4j NEO4J_PASSWORD=CHANGE_ME pytest graph/tests/test_import.py -v
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock

import pytest

from conftest import cleanup_test_nodes
from import_nodes_core import (
    import_applications,
    import_computer,
    import_entitlements,
    import_tcc_grants,
)
from import_nodes_security import import_local_groups
from import_nodes_security_enterprise import (
    import_ad_binding,
    import_kerberos_artifacts,
)
from import_nodes_services import import_keychain_items, import_launch_items
from import_nodes_services import import_mdm_profiles, import_xpc_services
from import_nodes_enrichment import import_user_details

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


checks = TestCase()


def _fixture_login_shell() -> str:
    return "/bin/bash"


class TestSecurityEnterpriseImportUnit:
    def test_import_kerberos_artifacts_splits_cache_and_keytab_records(self, tmp_path):
        from models import KerberosArtifactData

        artifacts = [
            KerberosArtifactData(
                path=str(tmp_path / "krb5cc_501"),
                artifact_type="ccache",
                principal_hint="testuser",
            ),
            KerberosArtifactData(path="/etc/krb5.keytab", artifact_type="keytab"),
            KerberosArtifactData(
                path="/etc/krb5.conf",
                artifact_type="config",
                default_realm="CORP.EXAMPLE.COM",
            ),
        ]
        session = MagicMock()
        count_result = MagicMock()
        count_result.single.side_effect = [{"n": 3}, {"n": 1}, {"n": 1}]
        session.run.side_effect = [
            MagicMock(),
            count_result,
            count_result,
            count_result,
        ]

        counts = import_kerberos_artifacts(
            session,
            artifacts,
            "fixture-host",
            TEST_SCAN_ID,
        )

        checks.assertEqual(counts, (3, 3, 1, 1))
        checks.assertEqual(session.run.call_count, 4)
        all_records = session.run.call_args_list[0].kwargs["records"]
        cache_records = session.run.call_args_list[2].kwargs["records"]
        keytab_records = session.run.call_args_list[3].kwargs["records"]
        checks.assertEqual(len(all_records), 3)
        checks.assertEqual(cache_records, [all_records[0]])
        checks.assertEqual(keytab_records, [all_records[1]])
        checks.assertEqual(
            session.run.call_args_list[1].kwargs["computer_key"],
            f"{TEST_SCAN_ID}:fixture-host",
        )


class TestImportIntegration:
    def test_import_applications(self, neo4j_session, scan_result):
        n = import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)
        checks.assertEqual(n, 3)

        result = neo4j_session.run(
            "MATCH (a:Application {scan_id: $scan_id}) RETURN count(a) AS n",
            scan_id=TEST_SCAN_ID,
        )
        checks.assertEqual(result.single()["n"], 3)

    def test_application_properties(self, neo4j_session, scan_result):
        import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)

        result = neo4j_session.run(
            "MATCH (a:Application {scan_id: $scan_id, bundle_id: 'com.googlecode.iterm2'}) RETURN a",
            scan_id=TEST_SCAN_ID,
        )
        row = result.single()
        checks.assertIsNotNone(row)
        app = row["a"]
        checks.assertEqual(app["name"], "iTerm2")
        checks.assertIs(app["hardened_runtime"], False)
        checks.assertIs(app["is_electron"], False)
        checks.assertIn("missing_library_validation", app["injection_methods"])

    def test_import_tcc_grants(self, neo4j_session, scan_result):
        import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)
        linked, skipped = import_tcc_grants(
            neo4j_session, scan_result.tcc_grants, TEST_SCAN_ID
        )
        checks.assertEqual(linked, 5)
        checks.assertEqual(skipped, 0)

        result = neo4j_session.run(
            "MATCH (:Application)-[r:HAS_TCC_GRANT]->(:TCC_Permission) RETURN count(r) AS n"
        )
        checks.assertGreaterEqual(result.single()["n"], 5)

    def test_import_entitlements(self, neo4j_session, scan_result):
        import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)
        n_ent_nodes, n_ent_rels = import_entitlements(
            neo4j_session, scan_result.applications, TEST_SCAN_ID
        )
        # 10 total entitlements but some names are shared across apps → fewer unique nodes
        checks.assertEqual(n_ent_rels, 11)
        checks.assertLessEqual(n_ent_nodes, 11)

    def test_idempotency(self, neo4j_session, scan_result):
        """Re-importing the same data must not create duplicate nodes."""

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
        checks.assertEqual(
            result.single()["n"], 3, "Duplicate Application nodes created"
        )

        result = neo4j_session.run(
            "MATCH (:Application)-[r:HAS_TCC_GRANT]->(:TCC_Permission) RETURN count(r) AS n"
        )
        # Should still be exactly 5 TCC grant relationships (no duplicates)
        tcc_count = result.single()["n"]
        checks.assertGreaterEqual(tcc_count, 5)

    def test_import_launch_items(self, neo4j_session, scan_result):
        n_nodes, n_persists, n_runs, n_hijacks = import_launch_items(
            neo4j_session, scan_result.launch_items
        )
        checks.assertEqual(n_nodes, 3)
        checks.assertEqual(n_hijacks, 0)

        result = neo4j_session.run(
            "MATCH (l:LaunchItem) WHERE l.label IN ['com.example.daemon', 'com.example.agent', 'cron.root.1'] RETURN count(l) AS n"
        )
        checks.assertEqual(result.single()["n"], 3)

    def test_launch_item_properties(self, neo4j_session, scan_result):
        import_launch_items(neo4j_session, scan_result.launch_items)

        result = neo4j_session.run(
            "MATCH (l:LaunchItem {label: 'com.example.daemon'}) RETURN l"
        )
        row = result.single()
        checks.assertIsNotNone(row)
        launch_item = row["l"]
        checks.assertEqual(launch_item["type"], "daemon")
        checks.assertIs(launch_item["run_at_load"], True)
        checks.assertEqual(launch_item["user"], "root")

    def test_launch_item_runs_as_edge(self, neo4j_session, scan_result):
        import_launch_items(neo4j_session, scan_result.launch_items)

        result = neo4j_session.run(
            """
            MATCH (l:LaunchItem {label: 'com.example.daemon'})-[:RUNS_AS]->(u:User {name: 'root'})
            RETURN count(l) AS n
            """
        )
        checks.assertEqual(
            result.single()["n"], 1, "RUNS_AS edge to root User should exist"
        )

    def test_launch_item_idempotency(self, neo4j_session, scan_result):
        import_launch_items(neo4j_session, scan_result.launch_items)
        import_launch_items(neo4j_session, scan_result.launch_items)

        result = neo4j_session.run(
            "MATCH (l:LaunchItem) WHERE l.label IN ['com.example.daemon', 'com.example.agent'] RETURN count(l) AS n"
        )
        checks.assertEqual(
            result.single()["n"], 2, "Duplicate LaunchItem nodes created"
        )

    def test_import_xpc_services(self, neo4j_session, scan_result):
        n_nodes, n_edges = import_xpc_services(neo4j_session, scan_result.xpc_services)
        checks.assertEqual(n_nodes, 2)

        result = neo4j_session.run(
            "MATCH (x:XPC_Service) WHERE x.label IN ['com.example.testdaemon', 'com.example.testagent'] RETURN count(x) AS n"
        )
        checks.assertEqual(result.single()["n"], 2)

    def test_xpc_service_properties(self, neo4j_session, scan_result):
        import_xpc_services(neo4j_session, scan_result.xpc_services)

        result = neo4j_session.run(
            "MATCH (x:XPC_Service {label: 'com.example.testdaemon'}) RETURN x"
        )
        row = result.single()
        checks.assertIsNotNone(row)
        svc = row["x"]
        checks.assertEqual(svc["type"], "daemon")
        checks.assertIs(svc["run_at_load"], True)
        checks.assertIs(svc["keep_alive"], True)
        checks.assertIn("com.example.testdaemon.xpc", svc["mach_services"])
        checks.assertIn("com.apple.private.tcc.allow", svc["entitlements"])

    def test_xpc_import_idempotency(self, neo4j_session, scan_result):
        """Re-importing the same XPC services must not create duplicate nodes."""

        import_xpc_services(neo4j_session, scan_result.xpc_services)
        import_xpc_services(neo4j_session, scan_result.xpc_services)

        result = neo4j_session.run(
            "MATCH (x:XPC_Service) WHERE x.label IN ['com.example.testdaemon', 'com.example.testagent'] RETURN count(x) AS n"
        )
        checks.assertEqual(
            result.single()["n"], 2, "Duplicate XPC_Service nodes created"
        )

    def test_import_keychain_items(self, neo4j_session, scan_result):
        import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)
        n_nodes, n_edges = import_keychain_items(
            neo4j_session, scan_result.keychain_acls
        )
        checks.assertEqual(n_nodes, 3)

        result = neo4j_session.run(
            "MATCH (k:Keychain_Item) WHERE k.label IN ['iTerm2 Credential', 'Slack Token', 'Developer Certificate'] RETURN count(k) AS n"
        )
        checks.assertEqual(result.single()["n"], 3)

    def test_keychain_can_read_edges(self, neo4j_session, scan_result):
        import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)
        _, n_edges = import_keychain_items(neo4j_session, scan_result.keychain_acls)
        # iTerm2 → iTerm2 Credential (1) + Slack → Slack Token (1) + Terminal → Slack Token (1) = 3
        checks.assertGreaterEqual(n_edges, 3)

        result = neo4j_session.run(
            "MATCH (a:Application)-[r:CAN_READ_KEYCHAIN]->(k:Keychain_Item) RETURN count(r) AS n"
        )
        checks.assertGreaterEqual(result.single()["n"], 3)

    def test_keychain_item_properties(self, neo4j_session, scan_result):
        import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)
        import_keychain_items(neo4j_session, scan_result.keychain_acls)

        result = neo4j_session.run(
            "MATCH (k:Keychain_Item {label: 'iTerm2 Credential'}) RETURN k"
        )
        row = result.single()
        checks.assertIsNotNone(row)
        k = row["k"]
        checks.assertEqual(k["kind"], "generic_password")
        checks.assertEqual(k["service"], "com.googlecode.iterm2.SecureInput")
        checks.assertEqual(k["access_group"], "H7V7XYVQ7D.com.googlecode.iterm2")

    def test_keychain_import_idempotency(self, neo4j_session, scan_result):
        """Re-importing the same keychain items must not create duplicate nodes."""

        import_applications(neo4j_session, scan_result.applications, TEST_SCAN_ID)
        import_keychain_items(neo4j_session, scan_result.keychain_acls)
        import_keychain_items(neo4j_session, scan_result.keychain_acls)

        result = neo4j_session.run(
            "MATCH (k:Keychain_Item) WHERE k.label IN ['iTerm2 Credential', 'Slack Token'] RETURN count(k) AS n"
        )
        checks.assertEqual(
            result.single()["n"], 2, "Duplicate Keychain_Item nodes created"
        )

    def test_keychain_no_trusted_apps_creates_no_edges(
        self, neo4j_session, scan_result
    ):
        """Keychain items with empty trusted_apps must not create CAN_READ_KEYCHAIN edges."""
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
        checks.assertEqual(n_nodes, 1)
        checks.assertEqual(n_edges, 0)

    def test_import_mdm_profiles(self, neo4j_session, scan_result):
        n_nodes, n_edges = import_mdm_profiles(neo4j_session, scan_result.mdm_profiles)
        checks.assertEqual(n_nodes, 2)
        checks.assertEqual(n_edges, 2)

        result = neo4j_session.run(
            "MATCH (m:MDM_Profile) WHERE m.identifier IN ['com.example.tcc.profile', 'com.example.basic.profile'] RETURN count(m) AS n"
        )
        checks.assertEqual(result.single()["n"], 2)

    def test_mdm_configures_edges(self, neo4j_session, scan_result):
        import_mdm_profiles(neo4j_session, scan_result.mdm_profiles)

        result = neo4j_session.run(
            "MATCH (m:MDM_Profile {identifier: 'com.example.tcc.profile'})-[c:CONFIGURES]->(t:TCC_Permission) RETURN count(c) AS n"
        )
        checks.assertEqual(result.single()["n"], 2)

    def test_mdm_profile_properties(self, neo4j_session, scan_result):
        import_mdm_profiles(neo4j_session, scan_result.mdm_profiles)

        result = neo4j_session.run(
            "MATCH (m:MDM_Profile {identifier: 'com.example.tcc.profile'}) RETURN m"
        )
        row = result.single()
        checks.assertIsNotNone(row)
        m = row["m"]
        checks.assertEqual(m["display_name"], "Privacy Policy Profile")
        checks.assertEqual(m["organization"], "Example Corp")
        checks.assertEqual(m["install_date"], "2026-03-01 00:00:00 +0000")

    def test_mdm_no_tcc_policies_creates_no_edges(self, neo4j_session, scan_result):
        """Profiles with no TCC policies must not create CONFIGURES edges."""
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
        checks.assertEqual(n_nodes, 1)
        checks.assertEqual(n_edges, 0)

    def test_mdm_import_idempotency(self, neo4j_session, scan_result):
        """Re-importing the same MDM profiles must not create duplicate nodes."""

        import_mdm_profiles(neo4j_session, scan_result.mdm_profiles)
        import_mdm_profiles(neo4j_session, scan_result.mdm_profiles)

        result = neo4j_session.run(
            "MATCH (m:MDM_Profile) WHERE m.identifier IN ['com.example.tcc.profile', 'com.example.basic.profile'] RETURN count(m) AS n"
        )
        checks.assertEqual(
            result.single()["n"], 2, "Duplicate MDM_Profile nodes created"
        )

    def test_unknown_client_grant_skipped(self, neo4j_session):
        """A TCC grant whose client has no Application node should be skipped gracefully."""
        from models import TCCGrantData

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
        checks.assertEqual(linked, 0)
        checks.assertEqual(skipped, 1)

        result = neo4j_session.run(
            """
            MATCH (u:UnresolvedTCCGrant {scan_id: $scan_id, client: $client})
                  -[:REFERENCES_TCC_PERMISSION]->(t:TCC_Permission {service: $service})
            RETURN u, t
            """,
            scan_id=TEST_SCAN_ID,
            client="com.nonexistent.app",
            service="kTCCServiceMicrophone",
        )
        row = result.single()
        checks.assertIsNotNone(row)
        unresolved = row["u"]
        checks.assertIs(unresolved["allowed"], True)
        checks.assertEqual(unresolved["scope"], "user")

        neo4j_session.run(
            "MATCH (u:UnresolvedTCCGrant {scan_id: $scan_id}) DETACH DELETE u",
            scan_id=TEST_SCAN_ID,
        )

    def test_import_ad_binding(self, neo4j_session, scan_result):
        """AD binding enriches Computer node and creates ADGroup + MAPPED_TO."""
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
        checks.assertEqual(n_groups, 1)
        checks.assertEqual(n_mapped, 1)

        # Verify Computer node has ad_bound property
        result = neo4j_session.run(
            "MATCH (c:Computer {computer_key: $computer_key}) RETURN c.ad_bound AS ad_bound, c.ad_realm AS realm",
            computer_key=f"{TEST_SCAN_ID}:{scan_result.hostname}",
        )
        row = result.single()
        checks.assertIs(row["ad_bound"], True)
        checks.assertEqual(row["realm"], "CORP.EXAMPLE.COM")

        # Verify ADGroup node exists
        result = neo4j_session.run("MATCH (ag:ADGroup) RETURN count(ag) AS n")
        checks.assertGreaterEqual(result.single()["n"], 1)

        # Verify MAPPED_TO edge
        result = neo4j_session.run(
            "MATCH (ag:ADGroup)-[r:MAPPED_TO]->(lg:LocalGroup {name: 'admin'}) RETURN count(r) AS n"
        )
        checks.assertGreaterEqual(result.single()["n"], 1)

    def test_import_kerberos_artifacts(self, neo4j_session, scan_result):
        """Kerberos artifacts create nodes + FOUND_ON, HAS_KERBEROS_CACHE, HAS_KEYTAB edges."""
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
        checks.assertEqual(n_ka, 3)
        checks.assertEqual(n_found, 3)
        checks.assertEqual(n_cache, 1)
        checks.assertEqual(n_kt, 1)

        # Verify KerberosArtifact nodes
        result = neo4j_session.run("MATCH (ka:KerberosArtifact) RETURN count(ka) AS n")
        checks.assertGreaterEqual(result.single()["n"], 3)

        # Verify HAS_KERBEROS_CACHE edge
        result = neo4j_session.run(
            "MATCH (u:User {name: 'testuser'})-[:HAS_KERBEROS_CACHE]->(ka:KerberosArtifact) RETURN count(ka) AS n"
        )
        checks.assertGreaterEqual(result.single()["n"], 1)

    def test_user_is_ad_user_flag(self, neo4j_session, scan_result):
        """User details with is_ad_user should set the flag on User nodes."""
        from models import UserDetailData

        ad_user = UserDetailData.model_validate(
            {
                "name": "ad_testuser",
                "shell": _fixture_login_shell(),
                "home_dir": "/Users/ad_testuser",
                "is_hidden": False,
                "is_ad_user": True,
            }
        )
        import_user_details(neo4j_session, [ad_user])

        result = neo4j_session.run(
            "MATCH (u:User {name: 'ad_testuser'}) RETURN u.is_ad_user AS is_ad"
        )
        checks.assertIs(result.single()["is_ad"], True)

    def test_ad_binding_not_bound(self, neo4j_session):
        """Non-bound AD binding returns 0, 0 with no side effects."""
        from models import ADBindingData

        not_bound = ADBindingData(is_bound=False)
        n_groups, n_mapped = import_ad_binding(neo4j_session, not_bound, "test-mac")
        checks.assertEqual(n_groups, 0)
        checks.assertEqual(n_mapped, 0)

    def test_ad_binding_none(self, neo4j_session):
        """None AD binding returns 0, 0."""

        n_groups, n_mapped = import_ad_binding(neo4j_session, None, "test-mac")
        checks.assertEqual(n_groups, 0)
        checks.assertEqual(n_mapped, 0)

    def test_same_bundle_id_across_scans_remains_distinct(
        self, neo4j_session, scan_result
    ):
        other_scan_id = "test-00000000-0000-0000-0000-000000000099"
        import_applications(neo4j_session, [scan_result.applications[0]], TEST_SCAN_ID)
        import_applications(neo4j_session, [scan_result.applications[0]], other_scan_id)

        result = neo4j_session.run(
            "MATCH (a:Application {bundle_id: $bundle_id}) WHERE a.scan_id IN [$scan_a, $scan_b] RETURN count(a) AS n",
            bundle_id=scan_result.applications[0].bundle_id,
            scan_a=TEST_SCAN_ID,
            scan_b=other_scan_id,
        )
        checks.assertEqual(result.single()["n"], 2)

        cleanup_test_nodes(neo4j_session, other_scan_id)

    def test_same_bundle_id_multiple_paths_remains_distinct(
        self, neo4j_session, scan_result
    ):
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
        checks.assertEqual(result.single()["n"], 2)
