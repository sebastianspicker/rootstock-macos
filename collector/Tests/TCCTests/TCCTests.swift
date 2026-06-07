import XCTest
import SQLite3
@testable import TCC
import Models

final class TCCTests: XCTestCase {

    // MARK: - Fixture helpers

    /// Executes a SQL statement using prepare/step (avoids sqlite3_exec).
    @discardableResult
    private func runSQL(_ sql: String, on db: OpaquePointer?) -> Int32 {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            return SQLITE_ERROR
        }
        defer { sqlite3_finalize(stmt) }
        return sqlite3_step(stmt)
    }

    /// Create a synthetic TCC.db at the given path with sample entries.
    private func makeFixtureDB(at path: String) {
        var db: OpaquePointer?
        sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil)
        defer { sqlite3_close(db) }

        runSQL("""
            CREATE TABLE access (
                service        TEXT NOT NULL,
                client         TEXT NOT NULL,
                client_type    INTEGER NOT NULL,
                auth_value     INTEGER NOT NULL,
                auth_reason    INTEGER NOT NULL,
                auth_version   INTEGER NOT NULL DEFAULT 1,
                csreq          BLOB,
                policy_id      INTEGER,
                indirect_object_identifier_type INTEGER,
                indirect_object_identifier      TEXT DEFAULT 'UNUSED',
                indirect_object_code_identity   BLOB,
                flags          INTEGER,
                last_modified  INTEGER NOT NULL,
                pid            INTEGER,
                pid_version    INTEGER,
                boot_uuid      TEXT DEFAULT 'UNUSED',
                last_reminded  INTEGER NOT NULL DEFAULT 0
            )
            """, on: db)

        // 7 rows: 5 allowed, 1 denied, 1 unknown (auth_value=1 → skipped)
        let inserts = [
            // Allowed: Full Disk Access
            "INSERT INTO access (service,client,client_type,auth_value,auth_reason,last_modified) VALUES ('kTCCServiceSystemPolicyAllFiles','com.example.app1',0,2,1,1700000001)",
            // Allowed: Accessibility
            "INSERT INTO access (service,client,client_type,auth_value,auth_reason,last_modified) VALUES ('kTCCServiceAccessibility','com.example.app2',0,2,2,1700000002)",
            // Denied: Screen Recording (absolute-path client)
            "INSERT INTO access (service,client,client_type,auth_value,auth_reason,last_modified) VALUES ('kTCCServiceScreenCapture','/usr/bin/screenrecorder',1,0,1,1700000003)",
            // Allowed: Microphone
            "INSERT INTO access (service,client,client_type,auth_value,auth_reason,last_modified) VALUES ('kTCCServiceMicrophone','com.example.app4',0,2,3,1700000004)",
            // Limited (auth_value=3): Camera
            "INSERT INTO access (service,client,client_type,auth_value,auth_reason,last_modified) VALUES ('kTCCServiceCamera','com.example.app5',0,3,4,1700000005)",
            // Unknown (auth_value=1): MUST be skipped by TCCDataSource
            "INSERT INTO access (service,client,client_type,auth_value,auth_reason,last_modified) VALUES ('kTCCServiceMicrophone','com.example.skip',0,1,1,1700000006)",
            // Allowed: unrecognised service (tests fallback display name)
            "INSERT INTO access (service,client,client_type,auth_value,auth_reason,last_modified) VALUES ('kTCCServiceFuture','com.example.app7',0,2,1,1700000007)",
        ]
        for sql in inserts {
            runSQL(sql, on: db)
        }
    }

    private func makeMinimalDB(at path: String, insertStatements: [String]) {
        var db: OpaquePointer?
        sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil)
        defer { sqlite3_close(db) }

        runSQL("""
            CREATE TABLE access (
                service        TEXT,
                client         TEXT,
                client_type    INTEGER,
                auth_value     INTEGER,
                auth_reason    INTEGER,
                last_modified  INTEGER
            )
            """, on: db)

        for sql in insertStatements {
            runSQL(sql, on: db)
        }
    }

    // MARK: - SQLiteDatabase tests

    func testSQLiteDatabaseReadsRows() throws {
        let path = NSTemporaryDirectory() + "tcc-test-\(UUID().uuidString).db"
        defer { try? FileManager.default.removeItem(atPath: path) }
        makeFixtureDB(at: path)

        let db = try SQLiteDatabase(path: path)
        let rows = try db.query("SELECT * FROM access")
        XCTAssertEqual(rows.count, 7)
    }

    func testSQLiteDatabaseColumnTypes() throws {
        let path = NSTemporaryDirectory() + "tcc-test-\(UUID().uuidString).db"
        defer { try? FileManager.default.removeItem(atPath: path) }
        makeFixtureDB(at: path)

        let db = try SQLiteDatabase(path: path)
        let rows = try db.query("SELECT service, client_type, last_modified FROM access LIMIT 1")
        XCTAssertEqual(rows.count, 1)

        let row = rows[0]
        XCTAssertTrue(row["service"] is String, "service should be String")
        XCTAssertTrue(row["client_type"] is Int, "client_type should be Int")
        XCTAssertTrue(row["last_modified"] is Int, "last_modified should be Int")
    }

    func testSQLiteDatabaseNonexistentPath() {
        XCTAssertThrowsError(try SQLiteDatabase(path: "/nonexistent/path/TCC.db")) { error in
            XCTAssertTrue(error is SQLiteError, "Expected SQLiteError, got \(error)")
        }
    }

    // MARK: - TCCDataSource tests

    func testTCCDataSourceParsesFixture() async throws {
        let path = NSTemporaryDirectory() + "tcc-test-\(UUID().uuidString).db"
        defer { try? FileManager.default.removeItem(atPath: path) }
        makeFixtureDB(at: path)

        let source = TCCDataSource(userDBPath: path, systemDBPath: nil)
        let result = await source.collect()

        // 7 rows, 1 with auth_value=1 skipped → 6 grants
        XCTAssertEqual(result.nodes.count, 6)
        XCTAssertTrue(result.errors.isEmpty)

        let grants = result.nodes.compactMap { $0 as? TCCGrant }
        XCTAssertEqual(grants.count, 6)

        // All grants must have "user" scope
        XCTAssertTrue(grants.allSatisfy { $0.scope == "user" })

        // Known service display name
        let fda = grants.first { $0.service == "kTCCServiceSystemPolicyAllFiles" }
        XCTAssertNotNil(fda)
        XCTAssertEqual(fda?.displayName, "Full Disk Access")
        XCTAssertEqual(fda?.authValue, 2)

        // Unknown service falls back to raw identifier
        let future = grants.first { $0.service == "kTCCServiceFuture" }
        XCTAssertNotNil(future)
        XCTAssertEqual(future?.displayName, "kTCCServiceFuture")

        XCTAssertNil(grants.first { $0.client == "com.example.skip" })
        XCTAssertEqual(grants.first { $0.client == "/usr/bin/screenrecorder" }?.authValue, 0)
        XCTAssertEqual(grants.first { $0.client == "com.example.app5" }?.authValue, 3)

        // lastModified is populated
        XCTAssertGreaterThan(fda?.lastModified ?? 0, 0)
    }

    func testTCCDataSourceMissingDBIsGraceful() async {
        let source = TCCDataSource(userDBPath: "/nonexistent/path/TCC.db", systemDBPath: nil)
        let result = await source.collect()

        XCTAssertTrue(result.nodes.isEmpty, "Expected no nodes from missing DB")
        XCTAssertFalse(result.errors.isEmpty, "Expected an error for missing DB")
        XCTAssertEqual(result.errors.first?.recoverable, true)
    }

    func testTCCDataSourceSystemDBErrorDoesNotAbort() async throws {
        let path = NSTemporaryDirectory() + "tcc-test-\(UUID().uuidString).db"
        defer { try? FileManager.default.removeItem(atPath: path) }
        makeFixtureDB(at: path)

        let source = TCCDataSource(userDBPath: path, systemDBPath: "/nonexistent/system/TCC.db")
        let result = await source.collect()

        // User DB succeeded → 6 grants; system DB failed → 1 error
        let grants = result.nodes.compactMap { $0 as? TCCGrant }
        XCTAssertEqual(grants.count, 6)
        XCTAssertEqual(result.errors.count, 1)
        XCTAssertEqual(result.errors.first?.recoverable, true)
    }

    func testTCCDataSourceReadsUserBeforeSystemDB() async throws {
        let userPath = NSTemporaryDirectory() + "tcc-user-\(UUID().uuidString).db"
        let systemPath = NSTemporaryDirectory() + "tcc-system-\(UUID().uuidString).db"
        defer {
            try? FileManager.default.removeItem(atPath: userPath)
            try? FileManager.default.removeItem(atPath: systemPath)
        }

        makeMinimalDB(
            at: userPath,
            insertStatements: [
                "INSERT INTO access (service,client,client_type,auth_value,auth_reason,last_modified) VALUES ('kTCCServiceCamera','com.example.user',0,2,1,1700000010)",
            ]
        )
        makeMinimalDB(
            at: systemPath,
            insertStatements: [
                "INSERT INTO access (service,client,client_type,auth_value,auth_reason,last_modified) VALUES ('kTCCServiceMicrophone','com.example.system',0,2,1,1700000011)",
            ]
        )

        let source = TCCDataSource(userDBPath: userPath, systemDBPath: systemPath)
        let result = await source.collect()
        let grants = result.nodes.compactMap { $0 as? TCCGrant }

        XCTAssertTrue(result.errors.isEmpty)
        XCTAssertEqual(grants.map(\.scope), ["user", "system"])
        XCTAssertEqual(grants.map(\.client), ["com.example.user", "com.example.system"])
    }

    // MARK: - TCC schema / MacOSVersion tests

    func testColumnNamesDetectionViaPRAGMA() throws {
        let path = NSTemporaryDirectory() + "tcc-pragma-\(UUID().uuidString).db"
        defer { try? FileManager.default.removeItem(atPath: path) }
        makeFixtureDB(at: path)

        let db = try SQLiteDatabase(path: path)
        let columns = db.columnNames(table: "access")
        for col in ["service", "client", "client_type", "auth_value", "auth_reason", "last_modified"] {
            XCTAssertTrue(columns.contains(col), "Expected column '\(col)'")
        }
        XCTAssertTrue(columns.contains("csreq"), "Expected optional column 'csreq'")
    }

    func testMalformedDBProducesGracefulErrorViaDataSource() async throws {
        let path = NSTemporaryDirectory() + "tcc-bad-\(UUID().uuidString).db"
        defer { try? FileManager.default.removeItem(atPath: path) }
        var raw: OpaquePointer?
        sqlite3_open_v2(path, &raw, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil)
        runSQL("CREATE TABLE access (service TEXT, wrong_col INTEGER)", on: raw)
        sqlite3_close(raw)

        let source = TCCDataSource(userDBPath: path, systemDBPath: nil, macOSVersion: .sonoma)
        let result = await source.collect()
        XCTAssertTrue(result.nodes.isEmpty)
        XCTAssertFalse(result.errors.isEmpty)
        XCTAssertEqual(result.errors.first?.recoverable, true)
    }

    func testMalformedRowsProduceRecoverableErrorViaDataSource() async throws {
        let path = NSTemporaryDirectory() + "tcc-malformed-row-\(UUID().uuidString).db"
        defer { try? FileManager.default.removeItem(atPath: path) }
        makeMinimalDB(
            at: path,
            insertStatements: [
                "INSERT INTO access (service,client,client_type,auth_value,auth_reason,last_modified) VALUES ('kTCCServiceCamera','com.example.valid',0,2,1,1700000020)",
                "INSERT INTO access (service,client,client_type,auth_value,auth_reason,last_modified) VALUES ('kTCCServiceMicrophone',NULL,0,2,1,1700000021)",
            ]
        )

        let source = TCCDataSource(userDBPath: path, systemDBPath: nil)
        let result = await source.collect()
        let grants = result.nodes.compactMap { $0 as? TCCGrant }

        XCTAssertEqual(result.errors.count, 1)
        XCTAssertEqual(result.errors.first?.recoverable, true)
        XCTAssertTrue(result.errors.first?.message.contains("Skipped malformed TCC row") ?? false)
        XCTAssertEqual(grants.map(\.client), ["com.example.valid"])
    }

    func testTCCAccessProbeRequiresSuccessfulQuery() throws {
        let path = NSTemporaryDirectory() + "tcc-probe-\(UUID().uuidString).db"
        defer { try? FileManager.default.removeItem(atPath: path) }
        makeMinimalDB(at: path, insertStatements: [])

        XCTAssertTrue(TCCAccessProbe.canQueryDatabase(at: path))
        XCTAssertFalse(TCCAccessProbe.canQueryDatabase(at: "/nonexistent/path/TCC.db"))
    }

    func testTCCAccessProbeRejectsUnreadableSchema() throws {
        let path = NSTemporaryDirectory() + "tcc-probe-bad-\(UUID().uuidString).db"
        defer { try? FileManager.default.removeItem(atPath: path) }
        var raw: OpaquePointer?
        sqlite3_open_v2(path, &raw, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil)
        runSQL("CREATE TABLE not_access (service TEXT)", on: raw)
        sqlite3_close(raw)

        XCTAssertFalse(TCCAccessProbe.canQueryDatabase(at: path))
    }

    func testMacOSVersionFromMajorVersion() {
        XCTAssertEqual(MacOSVersion.from(majorVersion: 14), .sonoma)
        XCTAssertEqual(MacOSVersion.from(majorVersion: 15), .sequoia)
        XCTAssertEqual(MacOSVersion.from(majorVersion: 26), .tahoe)
        if case .unknown(let major, _) = MacOSVersion.from(majorVersion: 99) {
            XCTAssertEqual(major, 99)
        } else {
            XCTFail("Expected .unknown for majorVersion 99")
        }
    }

    func testMacOSVersionComparable() {
        XCTAssertLessThan(MacOSVersion.sonoma, .sequoia)
        XCTAssertLessThan(MacOSVersion.sequoia, .tahoe)
        XCTAssertGreaterThan(MacOSVersion.tahoe, .sonoma)
    }

    func testMacOSVersionDisplayStrings() {
        XCTAssertEqual(MacOSVersion.sonoma.displayString,  "macOS 14 Sonoma")
        XCTAssertEqual(MacOSVersion.sequoia.displayString, "macOS 15 Sequoia")
        XCTAssertEqual(MacOSVersion.tahoe.displayString,   "macOS 26 Tahoe")
    }

    func testMacOSVersionDetectReturnsValidValue() {
        let osVersion = ProcessInfo.processInfo.operatingSystemVersion
        let version = MacOSVersion.detect()
        let expected = MacOSVersion.from(
            majorVersion: osVersion.majorVersion,
            minorVersion: osVersion.minorVersion
        )
        XCTAssertFalse(version.displayString.isEmpty)
        XCTAssertEqual(version, expected)
    }

    func testSequoiaErrorMessageContainsGuidance() async {
        let source = TCCDataSource(
            userDBPath: "/nonexistent/TCC.db",
            systemDBPath: nil,
            macOSVersion: .sequoia
        )
        let result = await source.collect()
        XCTAssertFalse(result.errors.isEmpty)
        let msg = result.errors.first?.message ?? ""
        XCTAssertTrue(msg.contains("Full Disk Access"), "Expected FDA guidance in Sequoia error: \(msg)")
    }

    func testTahoeErrorMessageContainsGuidance() async {
        let source = TCCDataSource(
            userDBPath: "/nonexistent/TCC.db",
            systemDBPath: nil,
            macOSVersion: .tahoe
        )
        let result = await source.collect()
        XCTAssertFalse(result.errors.isEmpty)
        let msg = result.errors.first?.message ?? ""
        XCTAssertTrue(msg.contains("Full Disk Access"), "Expected FDA guidance in Tahoe error: \(msg)")
    }

    // MARK: - TCCServiceRegistry tests

    func testKnownServiceDisplayNames() {
        let cases: [(String, String)] = [
            ("kTCCServiceSystemPolicyAllFiles",         "Full Disk Access"),
            ("kTCCServiceAccessibility",                "Accessibility"),
            ("kTCCServiceScreenCapture",                "Screen Recording"),
            ("kTCCServiceMicrophone",                   "Microphone"),
            ("kTCCServiceCamera",                       "Camera"),
            ("kTCCServiceAppleEvents",                  "Automation"),
            ("kTCCServiceListenEvent",                  "Input Monitoring"),
            ("kTCCServiceSystemPolicyDesktopFolder",    "Desktop Folder"),
            ("kTCCServiceSystemPolicyDocumentsFolder",  "Documents Folder"),
            ("kTCCServiceSystemPolicyDownloadsFolder",  "Downloads Folder"),
            ("kTCCServiceSystemPolicyRemovableVolumes", "Removable Volumes"),
            ("kTCCServiceSystemPolicyNetworkVolumes",   "Network Volumes"),
            ("kTCCServiceEndpointSecurityClient",       "Endpoint Security"),
            ("kTCCServiceLocation",                     "Location Services"),
            ("kTCCServicePhotos",                       "Photos"),
        ]
        for (service, expected) in cases {
            XCTAssertEqual(
                TCCServiceRegistry.displayName(for: service), expected,
                "Display name mismatch for \(service)"
            )
        }
    }

    func testUnknownServiceFallsBackToRawIdentifier() {
        let unknown = "kTCCServiceUnknownFutureService"
        XCTAssertEqual(TCCServiceRegistry.displayName(for: unknown), unknown)
    }

    func testMacOS15ServicesAreKnown() {
        // Services added in macOS 15 Sequoia
        XCTAssertEqual(
            TCCServiceRegistry.displayName(for: "kTCCServiceGameCenterFriends"),
            "Game Center Friends"
        )
        XCTAssertEqual(
            TCCServiceRegistry.displayName(for: "kTCCServiceWebBrowserPublicKeyCredential"),
            "Web Browser Credentials"
        )
    }

    func testMacOS14ServiceIsKnown() {
        XCTAssertEqual(
            TCCServiceRegistry.displayName(for: "kTCCServiceSystemPolicySysAdminFiles"),
            "System Admin Files"
        )
    }

    func testIsKnownAPI() {
        XCTAssertTrue(TCCServiceRegistry.isKnown("kTCCServiceSystemPolicyAllFiles"))
        XCTAssertFalse(TCCServiceRegistry.isKnown("kTCCServiceNonExistent"))
    }

    func testMinimumVersionForSequoiaServices() {
        XCTAssertEqual(TCCServiceRegistry.minimumMajorVersion(for: "kTCCServiceGameCenterFriends"), 15)
        XCTAssertEqual(TCCServiceRegistry.minimumMajorVersion(for: "kTCCServiceWebBrowserPublicKeyCredential"), 15)
    }

    func testMinimumVersionForSonomaService() {
        XCTAssertEqual(TCCServiceRegistry.minimumMajorVersion(for: "kTCCServiceSystemPolicySysAdminFiles"), 14)
    }

    func testMinimumVersionForOlderServiceIsNil() {
        // Services that predate our versioning table return nil
        XCTAssertNil(TCCServiceRegistry.minimumMajorVersion(for: "kTCCServiceSystemPolicyAllFiles"))
        XCTAssertNil(TCCServiceRegistry.minimumMajorVersion(for: "kTCCServiceCamera"))
    }
}
