"""
test_queries.py — Tests for the Rootstock Cypher query library.

Two layers:
  1. File validation (no Neo4j): all .cypher files have correct headers.
  2. Syntax validation (Neo4j required): EXPLAIN each query to catch parse errors.
  3. Seeded execution (Neo4j required): representative queries return expected results.

Usage:
    pytest graph/tests/test_queries.py -v
    # With custom connection:
    NEO4J_URI=bolt://localhost:7687 pytest graph/tests/test_queries.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from conftest import cleanup_test_nodes

QUERIES_DIR = Path(__file__).parent.parent / "queries"
EXPECTED_QUERY_COUNT = 101
_REACHABILITY_QUERY_FILES = [
    "41-owned-to-fda.cypher",
    "42-owned-reachable.cypher",
    "44-paths-to-target.cypher",
    "45-owned-blast-radius.cypher",
    "47-owned-to-tier0.cypher",
    "57-tier0-inbound-control.cypher",
]
_REQUIRED_ATTACK_EDGES = {
    "CAN_CHANGE_PASSWORD",
    "CAN_READ_KERBEROS",
    "SHARES_KEYCHAIN_GROUP",
}

_HEADER_RE = re.compile(
    r"^//\s*(?P<key>Name|Purpose|Category|Severity|Parameters|CVE|ATT&CK):\s*(?P<value>.+)$",
    re.IGNORECASE,
)
_VALID_CATEGORIES = {"Red Team", "Blue Team", "Forensic"}
_VALID_SEVERITIES = {"Critical", "High", "Informational"}

TEST_SCAN_ID = "test-queries-00000000-0000-0000-0000-000000000003"


# ── Helpers ─────────────────────────────────────────────────────────────────

def _parse_header(path: Path) -> dict[str, str]:
    meta: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith("//"):
            if stripped:
                break
        m = _HEADER_RE.match(stripped)
        if m:
            meta[m.group("key").lower()] = m.group("value").strip()
    return meta


def _all_cypher_files() -> list[Path]:
    return sorted(QUERIES_DIR.glob("*.cypher"))


def _query_text(filename: str) -> str:
    return (QUERIES_DIR / filename).read_text(encoding="utf-8")


def _first_statement(cypher: str) -> str:
    """Extract the first non-comment Cypher statement."""
    non_comment_lines = [
        line for line in cypher.splitlines()
        if not line.strip().startswith("//")
    ]
    cleaned = "\n".join(non_comment_lines)
    for stmt in cleaned.split(";"):
        stripped = stmt.strip()
        if stripped:
            return stripped
    return cleaned.strip()


# ── Neo4j fixture ─────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def neo4j_session(neo4j_driver):
    """Module-scoped Neo4j session with cleanup."""
    with neo4j_driver.session() as session:
        yield session
    with neo4j_driver.session() as session:
        cleanup_test_nodes(session, TEST_SCAN_ID)


def _seed_minimal_graph(session) -> None:
    """
    Seed a minimal graph with known properties for query execution tests.
    Includes: 1 injectable FDA app, 1 Electron app, TCC grants, entitlements.
    """
    session.run(
        """
        MERGE (fda:TCC_Permission {service: 'kTCCServiceSystemPolicyAllFiles'})
        ON CREATE SET fda.display_name = 'Full Disk Access'

        MERGE (mic:TCC_Permission {service: 'kTCCServiceMicrophone'})
        ON CREATE SET mic.display_name = 'Microphone'

        MERGE (cam:TCC_Permission {service: 'kTCCServiceCamera'})
        ON CREATE SET cam.display_name = 'Camera'

        MERGE (appA:Application {bundle_id: 'com.rootstock.query.test.iterm'})
        SET appA.name = 'TestITerm',
            appA.path = '/Applications/TestITerm.app',
            appA.hardened_runtime = false,
            appA.library_validation = false,
            appA.is_electron = false,
            appA.is_system = false,
            appA.signed = true,
            appA.team_id = 'TESTTEAM01',
            appA.injection_methods = ['missing_library_validation', 'dyld_insert_via_entitlement'],
            appA.is_sip_protected = false,
            appA.scan_id = $scan_id

        MERGE (appB:Application {bundle_id: 'com.rootstock.query.test.electron'})
        SET appB.name = 'TestElectron',
            appB.path = '/Applications/TestElectron.app',
            appB.hardened_runtime = false,
            appB.library_validation = false,
            appB.is_electron = true,
            appB.is_system = false,
            appB.signed = true,
            appB.team_id = 'TESTTEAM02',
            appB.injection_methods = ['missing_library_validation', 'electron_env_var'],
            appB.is_sip_protected = false,
            appB.scan_id = $scan_id

        MERGE (appA)-[:HAS_TCC_GRANT {scope: 'user', allowed: true}]->(fda)
        MERGE (appB)-[:HAS_TCC_GRANT {scope: 'user', allowed: true}]->(mic)
        MERGE (appB)-[:HAS_TCC_GRANT {scope: 'user', allowed: true}]->(cam)

        MERGE (ent1:Entitlement {name: 'com.apple.security.cs.allow-dyld-environment-variables'})
        ON CREATE SET ent1.is_private = false, ent1.category = 'injection',
                      ent1.is_security_critical = true
        MERGE (ent2:Entitlement {name: 'com.apple.security.cs.disable-library-validation'})
        ON CREATE SET ent2.is_private = false, ent2.category = 'injection',
                      ent2.is_security_critical = true
        MERGE (ent3:Entitlement {name: 'com.apple.private.tcc.allow'})
        ON CREATE SET ent3.is_private = true, ent3.category = 'tcc',
                      ent3.is_security_critical = true

        MERGE (appA)-[:HAS_ENTITLEMENT]->(ent1)
        MERGE (appA)-[:HAS_ENTITLEMENT]->(ent2)
        MERGE (appB)-[:HAS_ENTITLEMENT]->(ent3)
        """,
        scan_id=TEST_SCAN_ID,
    )


# ── Layer 1: File validation (no Neo4j) ──────────────────────────────────────

class TestQueryFileStructure:
    def test_query_directory_exists(self):
        assert QUERIES_DIR.is_dir(), f"queries/ directory not found at {QUERIES_DIR}"

    def test_expected_query_count(self):
        files = _all_cypher_files()
        assert len(files) == EXPECTED_QUERY_COUNT, (
            f"Expected {EXPECTED_QUERY_COUNT} .cypher files, found {len(files)}"
        )

    def test_all_files_have_name_header(self):
        missing = []
        for path in _all_cypher_files():
            meta = _parse_header(path)
            if "name" not in meta or not meta["name"]:
                missing.append(path.name)
        assert not missing, f"Missing 'Name' header in: {missing}"

    def test_all_files_have_valid_category(self):
        bad = []
        for path in _all_cypher_files():
            meta = _parse_header(path)
            cat = meta.get("category", "")
            if cat not in _VALID_CATEGORIES:
                bad.append(f"{path.name}: '{cat}'")
        assert not bad, f"Invalid or missing 'Category' in: {bad}"

    def test_all_files_have_valid_severity(self):
        bad = []
        for path in _all_cypher_files():
            meta = _parse_header(path)
            sev = meta.get("severity", "")
            if sev not in _VALID_SEVERITIES:
                bad.append(f"{path.name}: '{sev}'")
        assert not bad, f"Invalid or missing 'Severity' in: {bad}"

    def test_all_files_non_empty(self):
        empty = []
        for path in _all_cypher_files():
            stmt = _first_statement(path.read_text(encoding="utf-8"))
            if not stmt:
                empty.append(path.name)
        assert not empty, f"Empty (no Cypher body) in: {empty}"

    def test_sequential_ids(self):
        """Query IDs should be consecutive from 01 to EXPECTED_QUERY_COUNT."""
        ids = []
        for path in _all_cypher_files():
            stem = path.stem
            qid = stem.split("-")[0]
            try:
                ids.append(int(qid))
            except ValueError:
                pytest.fail(f"Non-numeric query ID in filename: {path.name}")
        ids.sort()
        expected = list(range(1, EXPECTED_QUERY_COUNT + 1))
        assert ids == expected, f"Non-sequential IDs: got {ids}, expected {expected}"

    def test_all_queries_are_read_only(self):
        """Every .cypher file should pass the read-only Cypher validator."""
        from utils import validate_read_only_cypher
        failures = []
        for path in _all_cypher_files():
            cypher = path.read_text(encoding="utf-8")
            stmt = _first_statement(cypher)
            error = validate_read_only_cypher(stmt)
            if error:
                failures.append(f"{path.name}: {error}")
        assert not failures, "Queries that failed read-only validation:\n" + "\n".join(failures)

    def test_all_queries_parseable(self):
        """Every .cypher file should produce a non-empty first statement."""
        failures = []
        for path in _all_cypher_files():
            cypher = path.read_text(encoding="utf-8")
            stmt = _first_statement(cypher)
            if not stmt:
                failures.append(path.name)
        assert not failures, f"Queries with no parseable statement: {failures}"

    def test_cve_header_format_when_present(self):
        """CVE headers (when present) must contain valid CVE IDs."""
        cve_id_re = re.compile(r"CVE-\d{4}-\d+")
        bad = []
        for path in _all_cypher_files():
            meta = _parse_header(path)
            cve_val = meta.get("cve", "")
            if not cve_val:
                continue
            ids = cve_id_re.findall(cve_val)
            if not ids:
                bad.append(f"{path.name}: '{cve_val}' has no valid CVE IDs")
        assert not bad, f"Invalid CVE header format: {bad}"

    def test_attack_header_format_when_present(self):
        """ATT&CK headers (when present) must contain valid technique IDs."""
        tech_re = re.compile(r"T\d{4}(?:\.\d{3})?")
        bad = []
        for path in _all_cypher_files():
            meta = _parse_header(path)
            attack_val = meta.get("att&ck", "")
            if not attack_val:
                continue
            ids = tech_re.findall(attack_val)
            if not ids:
                bad.append(f"{path.name}: '{attack_val}' has no valid technique IDs")
        assert not bad, f"Invalid ATT&CK header format: {bad}"

    def test_reachability_queries_include_all_attack_edges(self):
        for filename in _REACHABILITY_QUERY_FILES:
            text = _query_text(filename)
            for edge in _REQUIRED_ATTACK_EDGES:
                assert edge in text, f"{filename} is missing {edge}"

    def test_query_62_bounds_certificate_chain_depth(self):
        text = _query_text("62-non-apple-ca-chain.cypher")
        assert "[:ISSUED_BY*0..10]" in text
        assert "[:ISSUED_BY*0..]" not in text


# ── Layer 2: Syntax validation (Neo4j EXPLAIN) ────────────────────────────────

class TestQuerySyntax:
    def test_all_queries_parse(self, neo4j_session):
        """EXPLAIN each query to verify Cypher syntax is valid."""
        failures = []
        for path in _all_cypher_files():
            cypher = path.read_text(encoding="utf-8")
            stmt = _first_statement(cypher)
            if not stmt:
                continue
            # Strip parameter references for EXPLAIN — use empty params
            try:
                neo4j_session.run(f"EXPLAIN {stmt}", {
                    "target_service": "kTCCServiceMicrophone",
                    "min_permissions": 3,
                    "team_id": "TEST",
                    "bundle_id": "com.example.test",
                    "days_old": 365,
                    "min_methods": 1,
                    "username": "testuser",
                    "scope": None,
                })
            except Exception as e:
                failures.append(f"{path.name}: {e}")
        assert not failures, "Cypher syntax errors:\n" + "\n".join(failures)


# ── Layer 3: Seeded execution tests ──────────────────────────────────────────

class TestQueryExecution:
    @pytest.fixture(autouse=True)
    def seed(self, neo4j_session):
        _seed_minimal_graph(neo4j_session)

    def test_query_01_injectable_fda_apps(self, neo4j_session):
        """Query 01 should find our injectable FDA app."""
        from infer_injection import infer
        infer(neo4j_session)

        cypher = (QUERIES_DIR / "01-injectable-fda-apps.cypher").read_text()
        stmt = _first_statement(cypher)
        result = list(neo4j_session.run(stmt, {}))
        assert len(result) >= 1, "Expected at least 1 injectable FDA app in seeded graph"

    def test_query_07_tcc_overview(self, neo4j_session):
        """Query 07 should return at least 1 TCC permission row."""
        cypher = (QUERIES_DIR / "07-tcc-grant-overview.cypher").read_text()
        stmt = _first_statement(cypher)
        result = list(neo4j_session.run(stmt, {}))
        assert len(result) >= 1, "Expected TCC grants in seeded graph"

    def test_query_16_tcc_grant_audit(self, neo4j_session):
        """Query 16 should return TCC grant detail rows."""
        cypher = (QUERIES_DIR / "16-tcc-grant-audit.cypher").read_text()
        stmt = _first_statement(cypher)
        result = list(neo4j_session.run(stmt, {"scope": None}))
        assert len(result) >= 1, "Expected TCC grant audit rows in seeded graph"

    def test_query_04_private_entitlements(self, neo4j_session):
        """Query 04 should find our app with com.apple.private.tcc.allow."""
        cypher = (QUERIES_DIR / "04-private-entitlement-audit.cypher").read_text()
        stmt = _first_statement(cypher)
        result = list(neo4j_session.run(stmt, {}))
        assert len(result) >= 1, "Expected at least 1 private entitlement in seeded graph"

    def test_query_45_owned_blast_radius(self, neo4j_session):
        """Query 45 should return results when nodes are marked owned."""
        # Mark one app as owned
        neo4j_session.run(
            """
            MATCH (a:Application {bundle_id: 'com.rootstock.query.test.iterm'})
            SET a.owned = true, a.owned_at = '2026-03-19T00:00:00Z'
            """
        )
        cypher = (QUERIES_DIR / "45-owned-blast-radius.cypher").read_text()
        stmt = _first_statement(cypher)
        result = list(neo4j_session.run(stmt, {}))
        assert len(result) >= 1, "Expected at least 1 owned node blast radius row"
        # Clean up owned markers
        neo4j_session.run("MATCH (n) WHERE n.owned = true REMOVE n.owned, n.owned_at")

    def test_query_46_tier_classification(self, neo4j_session):
        """Query 46 should return results after tier classification runs."""
        from tier_classification import classify
        classify(neo4j_session)
        cypher = (QUERIES_DIR / "46-tier-classification.cypher").read_text()
        stmt = _first_statement(cypher)
        result = list(neo4j_session.run(stmt, {}))
        assert len(result) >= 1, "Expected at least 1 classified app in seeded graph"
        # Clean up tier properties
        neo4j_session.run("MATCH (a:Application) WHERE a.tier IS NOT NULL REMOVE a.tier")

    def test_query_54_accessibility_abuse(self, neo4j_session):
        """Query 54 should execute without error on seeded graph."""
        from infer_accessibility import infer
        infer(neo4j_session)
        cypher = (QUERIES_DIR / "54-accessibility-abuse.cypher").read_text()
        stmt = _first_statement(cypher)
        result = list(neo4j_session.run(stmt, {}))
        # May return 0 rows if no A11Y grant in seed data; just verify it runs
        assert isinstance(result, list)

    def test_query_57_tier0_inbound(self, neo4j_session):
        """Query 57 should return results when tiers are classified."""
        from tier_classification import classify
        classify(neo4j_session)
        cypher = (QUERIES_DIR / "57-tier0-inbound-control.cypher").read_text()
        stmt = _first_statement(cypher)
        result = list(neo4j_session.run(stmt, {}))
        assert isinstance(result, list)
        # Clean up tier properties
        neo4j_session.run("MATCH (a:Application) WHERE a.tier IS NOT NULL REMOVE a.tier")

    def test_query_59_keychain_crown_jewels(self, neo4j_session):
        """Query 59 should return keychain items with sensitivity tiers."""
        cypher = (QUERIES_DIR / "59-keychain-crown-jewels.cypher").read_text()
        stmt = _first_statement(cypher)
        result = list(neo4j_session.run(stmt, {}))
        assert isinstance(result, list)

    def test_certificate_authority_nodes_created(self, neo4j_session):
        """Verify CertificateAuthority nodes can be created and queried."""
        neo4j_session.run(
            """
            MERGE (ca:CertificateAuthority {sha256: 'test-ca-sha256-root'})
            SET ca.common_name = 'Apple Root CA',
                ca.organization = 'Apple Inc.',
                ca.is_root = true
            MERGE (ca2:CertificateAuthority {sha256: 'test-ca-sha256-intermediate'})
            SET ca2.common_name = 'Developer ID Certification Authority',
                ca2.organization = 'Apple Inc.',
                ca2.is_root = false
            MERGE (ca2)-[:ISSUED_BY]->(ca)
            """
        )
        result = neo4j_session.run(
            "MATCH (ca:CertificateAuthority) RETURN count(ca) AS n"
        ).single()
        assert result["n"] >= 2, "Expected at least 2 CertificateAuthority nodes"

    def test_signed_by_ca_edges(self, neo4j_session):
        """Verify SIGNED_BY_CA edges link apps to correct CAs."""
        neo4j_session.run(
            """
            MERGE (ca:CertificateAuthority {sha256: 'test-ca-sha256-leaf'})
            SET ca.common_name = 'Developer ID Application: Test',
                ca.is_root = false
            WITH ca
            MATCH (a:Application {bundle_id: 'com.rootstock.query.test.iterm'})
            MERGE (a)-[:SIGNED_BY_CA]->(ca)
            """
        )
        result = neo4j_session.run(
            """
            MATCH (a:Application {bundle_id: 'com.rootstock.query.test.iterm'})-[:SIGNED_BY_CA]->(ca:CertificateAuthority)
            RETURN ca.common_name AS cn
            """
        ).single()
        assert result is not None, "Expected SIGNED_BY_CA edge from test app to CA"

    def test_issued_by_chain(self, neo4j_session):
        """Verify ISSUED_BY edges form correct hierarchy."""
        result = neo4j_session.run(
            """
            MATCH (child:CertificateAuthority {sha256: 'test-ca-sha256-intermediate'})
                  -[:ISSUED_BY]->(root:CertificateAuthority {sha256: 'test-ca-sha256-root'})
            RETURN root.common_name AS root_cn
            """
        ).single()
        assert result is not None, "Expected ISSUED_BY edge from intermediate to root"
        assert result["root_cn"] == "Apple Root CA"

    def test_query_60_expired_cert(self, neo4j_session):
        """Query 60 should find apps with expired certs and TCC grants."""
        neo4j_session.run(
            """
            MATCH (a:Application {bundle_id: 'com.rootstock.query.test.iterm'})
            SET a.is_certificate_expired = true,
                a.certificate_expires = '2024-01-01T00:00:00Z',
                a.signing_certificate_cn = 'Test Expired Cert'
            """
        )
        cypher = (QUERIES_DIR / "60-expired-cert-with-tcc.cypher").read_text()
        stmt = _first_statement(cypher)
        result = list(neo4j_session.run(stmt, {}))
        assert len(result) >= 1, "Expected at least 1 expired-cert app with TCC grants"
        # Clean up
        neo4j_session.run(
            """
            MATCH (a:Application {bundle_id: 'com.rootstock.query.test.iterm'})
            SET a.is_certificate_expired = false
            REMOVE a.certificate_expires, a.signing_certificate_cn
            """
        )

    def test_query_61_adhoc_signed(self, neo4j_session):
        """Query 61 should find ad-hoc signed apps with TCC grants."""
        neo4j_session.run(
            """
            MATCH (a:Application {bundle_id: 'com.rootstock.query.test.iterm'})
            SET a.is_adhoc_signed = true
            """
        )
        cypher = (QUERIES_DIR / "61-adhoc-signed-with-tcc.cypher").read_text()
        stmt = _first_statement(cypher)
        result = list(neo4j_session.run(stmt, {}))
        assert len(result) >= 1, "Expected at least 1 ad-hoc signed app with TCC grants"
        # Clean up
        neo4j_session.run(
            """
            MATCH (a:Application {bundle_id: 'com.rootstock.query.test.iterm'})
            SET a.is_adhoc_signed = false
            """
        )
