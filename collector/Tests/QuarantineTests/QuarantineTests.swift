import XCTest
import Darwin
@testable import Quarantine
import Models

final class QuarantineTests: XCTestCase {

    // MARK: - QuarantineInfo model tests

    func testQuarantineInfoJSONEncoding() throws {
        let info = QuarantineInfo(
            hasQuarantineFlag: true,
            quarantineAgent: "com.apple.Safari",
            quarantineTimestamp: "2024-06-15T10:30:00Z",
            wasUserApproved: true,
            wasTranslocated: false
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let data = try encoder.encode(info)
        let dict = try JSONSerialization.jsonObject(with: data) as? [String: Any]

        XCTAssertEqual(dict?["has_quarantine_flag"] as? Bool, true)
        XCTAssertEqual(dict?["quarantine_agent"] as? String, "com.apple.Safari")
        XCTAssertEqual(dict?["quarantine_timestamp"] as? String, "2024-06-15T10:30:00Z")
        XCTAssertEqual(dict?["was_user_approved"] as? Bool, true)
        XCTAssertEqual(dict?["was_translocated"] as? Bool, false)
    }

    func testQuarantineInfoJSONRoundTrip() throws {
        let original = QuarantineInfo(
            hasQuarantineFlag: true,
            quarantineAgent: "com.google.Chrome",
            quarantineTimestamp: "2024-01-01T00:00:00Z",
            wasUserApproved: false,
            wasTranslocated: true
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(QuarantineInfo.self, from: data)

        XCTAssertEqual(decoded.hasQuarantineFlag, original.hasQuarantineFlag)
        XCTAssertEqual(decoded.quarantineAgent, original.quarantineAgent)
        XCTAssertEqual(decoded.quarantineTimestamp, original.quarantineTimestamp)
        XCTAssertEqual(decoded.wasUserApproved, original.wasUserApproved)
        XCTAssertEqual(decoded.wasTranslocated, original.wasTranslocated)
    }

    func testQuarantineInfoNoFlagDefaults() throws {
        let info = QuarantineInfo(hasQuarantineFlag: false)
        let data = try JSONEncoder().encode(info)
        let dict = try JSONSerialization.jsonObject(with: data) as? [String: Any]

        XCTAssertEqual(dict?["has_quarantine_flag"] as? Bool, false)
        XCTAssertNil(dict?["quarantine_agent"] as? String)
        XCTAssertNil(dict?["quarantine_timestamp"] as? String)
        XCTAssertEqual(dict?["was_user_approved"] as? Bool, false)
        XCTAssertEqual(dict?["was_translocated"] as? Bool, false)
    }

    // MARK: - Quarantine hex string parsing tests

    func testParseFullQuarantineString() {
        // Flags: 0x0063 includes both 0x0040 (approved) and 0x0020 (translocated)
        let raw = "0063;5f3b3c00;com.apple.Safari;12345678-1234-1234-1234-123456789ABC"
        let info = QuarantineDataSource.parseQuarantineString(raw)

        XCTAssertTrue(info.hasQuarantineFlag)
        XCTAssertEqual(info.quarantineAgent, "com.apple.Safari")
        XCTAssertNotNil(info.quarantineTimestamp)
        XCTAssertTrue(info.wasUserApproved)  // 0x0063 has 0x0040 set
        XCTAssertTrue(info.wasTranslocated)  // 0x0063 has 0x0020 set
    }

    func testParseQuarantineStringNoApproval() {
        // Flags: 0x0003 — neither approval nor translocation
        let raw = "0003;5f3b3c00;com.google.Chrome;"
        let info = QuarantineDataSource.parseQuarantineString(raw)

        XCTAssertTrue(info.hasQuarantineFlag)
        XCTAssertEqual(info.quarantineAgent, "com.google.Chrome")
        XCTAssertFalse(info.wasUserApproved)
        XCTAssertFalse(info.wasTranslocated)
    }

    func testParseQuarantineStringApprovedOnly() {
        // Flags: 0x0043 — user approved (0x0040) but not translocated
        let raw = "0043;5f3b3c00;com.apple.Safari;UUID"
        let info = QuarantineDataSource.parseQuarantineString(raw)

        XCTAssertTrue(info.wasUserApproved)
        XCTAssertFalse(info.wasTranslocated)
    }

    func testParseQuarantineStringTranslocatedOnly() {
        // Flags: 0x0023 — translocated (0x0020) but not user approved
        let raw = "0023;5f3b3c00;com.apple.Safari;UUID"
        let info = QuarantineDataSource.parseQuarantineString(raw)

        XCTAssertFalse(info.wasUserApproved)
        XCTAssertTrue(info.wasTranslocated)
    }

    func testParseQuarantineStringEmptyAgent() {
        let raw = "0003;5f3b3c00;;"
        let info = QuarantineDataSource.parseQuarantineString(raw)

        XCTAssertTrue(info.hasQuarantineFlag)
        XCTAssertNil(info.quarantineAgent)
    }

    func testParseQuarantineStringMinimalComponents() {
        // Only flags present
        let raw = "0003"
        let info = QuarantineDataSource.parseQuarantineString(raw)

        XCTAssertTrue(info.hasQuarantineFlag)
        XCTAssertNil(info.quarantineAgent)
        XCTAssertNil(info.quarantineTimestamp)
        XCTAssertFalse(info.wasUserApproved)
        XCTAssertFalse(info.wasTranslocated)
    }

    func testParseQuarantineStringZeroTimestamp() {
        let raw = "0003;0;com.apple.Safari;UUID"
        let info = QuarantineDataSource.parseQuarantineString(raw)

        // Zero timestamp should be treated as absent
        XCTAssertNil(info.quarantineTimestamp)
    }

    // MARK: - Application integration tests

    func testApplicationWithQuarantineInfoEncoding() throws {
        let qInfo = QuarantineInfo(
            hasQuarantineFlag: true,
            quarantineAgent: "com.apple.Safari",
            wasUserApproved: true
        )
        let app = Application(
            name: "TestApp",
            bundleId: "com.example.test",
            path: "/Applications/TestApp.app",
            version: "1.0",
            teamId: nil,
            hardenedRuntime: true,
            libraryValidation: true,
            isElectron: false,
            isSystem: false,
            signed: true,
            quarantineInfo: qInfo
        )
        let data = try JSONEncoder().encode(app)
        let dict = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        XCTAssertNotNil(dict?["quarantine_info"])

        let qDict = dict?["quarantine_info"] as? [String: Any]
        XCTAssertEqual(qDict?["has_quarantine_flag"] as? Bool, true)
        XCTAssertEqual(qDict?["quarantine_agent"] as? String, "com.apple.Safari")
    }

    func testApplicationWithoutQuarantineInfoEncoding() throws {
        let app = Application(
            name: "TestApp",
            bundleId: "com.example.test",
            path: "/Applications/TestApp.app",
            version: "1.0",
            teamId: nil,
            hardenedRuntime: true,
            libraryValidation: true,
            isElectron: false,
            isSystem: false,
            signed: true
        )
        let data = try JSONEncoder().encode(app)
        let decoded = try JSONDecoder().decode(Application.self, from: data)
        XCTAssertNil(decoded.quarantineInfo)
    }

    func testApplicationRoundTripWithQuarantineInfo() throws {
        let qInfo = QuarantineInfo(
            hasQuarantineFlag: true,
            quarantineAgent: "com.apple.Safari",
            quarantineTimestamp: "2024-06-15T10:30:00Z",
            wasUserApproved: true,
            wasTranslocated: false
        )
        let original = Application(
            name: "TestApp",
            bundleId: "com.example.test",
            path: "/Applications/TestApp.app",
            version: "1.0",
            teamId: "TEST123",
            hardenedRuntime: true,
            libraryValidation: true,
            isElectron: false,
            isSystem: false,
            signed: true,
            quarantineInfo: qInfo
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(Application.self, from: data)

        XCTAssertNotNil(decoded.quarantineInfo)
        XCTAssertEqual(decoded.quarantineInfo?.hasQuarantineFlag, true)
        XCTAssertEqual(decoded.quarantineInfo?.quarantineAgent, "com.apple.Safari")
        XCTAssertEqual(decoded.quarantineInfo?.wasUserApproved, true)
        XCTAssertEqual(decoded.quarantineInfo?.wasTranslocated, false)
    }

    // MARK: - QuarantineDataSource enrichment tests

    func testEnrichApplications() {
        let source = QuarantineDataSource()
        var apps = [
            Application(
                name: "SystemApp",
                bundleId: "com.apple.system",
                path: "/System/Applications/System.app",
                version: "1.0",
                teamId: nil,
                hardenedRuntime: true,
                libraryValidation: true,
                isElectron: false,
                isSystem: true,
                signed: true
            ),
            Application(
                name: "UserApp",
                bundleId: "com.example.user",
                path: "/Applications/UserApp.app",
                version: "1.0",
                teamId: "TEST",
                hardenedRuntime: false,
                libraryValidation: false,
                isElectron: false,
                isSystem: false,
                signed: true
            ),
        ]
        // After enrichment, all apps should have quarantineInfo set
        // (even if hasQuarantineFlag is false for those without the xattr)
        _ = source.enrich(applications: &apps)
        XCTAssertNotNil(apps[0].quarantineInfo)
        XCTAssertNotNil(apps[1].quarantineInfo)
    }

    func testReadQuarantineFollowsSymlinkToTargetBundle() throws {
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("test-quarantine-symlink-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let realApp = tempDir.appendingPathComponent("Real.app")
        let linkedApp = tempDir.appendingPathComponent("Linked.app")
        try FileManager.default.createDirectory(at: realApp, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: linkedApp, withDestinationURL: realApp)

        let raw = "0043;5f3b3c00;com.apple.Safari;UUID"
        let bytes = Array(raw.utf8)
        let result = bytes.withUnsafeBufferPointer {
            setxattr(realApp.path, "com.apple.quarantine", $0.baseAddress, bytes.count, 0, 0)
        }
        XCTAssertEqual(result, 0)

        let info = QuarantineDataSource().readQuarantine(at: linkedApp.path)
        XCTAssertTrue(info.hasQuarantineFlag)
        XCTAssertEqual(info.quarantineAgent, "com.apple.Safari")
        XCTAssertTrue(info.wasUserApproved)
    }
}
