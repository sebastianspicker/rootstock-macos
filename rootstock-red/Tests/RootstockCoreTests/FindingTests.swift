import XCTest
@testable import RootstockCore

final class FindingTests: XCTestCase {
    func testFindingCodableRoundTrip() throws {
        let finding = Finding(id: "rootstock.check.host.identity", title: "Host identity", severity: .info, category: .host, resolution: .init(evidence: [Evidence(type: "host", detail: "ok")], attackTechniques: ["T1082"], remediation: ["n/a"]), runtime: .init(confidence: .high, dryRunSafe: true, opsecScore: 5))
        let data = try JSONEncoder().encode(finding)
        let decoded = try JSONDecoder().decode(Finding.self, from: data)
        XCTAssertEqual(decoded, finding)
    }

    func testConsentPolicy() {
        let policy = ConsentPolicy.labDefault
        let bad = ConsentTokens()
        XCTAssertFalse(bad.satisfies(policy))
        let good = ConsentTokens(iAmAuthorized: true, scope: "ENG-1", operatorName: "alice")
        XCTAssertTrue(good.satisfies(policy))
    }

    func testKillSwitchDetection() throws {
        // Ensure ensureNotDisabled does not throw when kill switch absent (normal dev machines).
        // If DISABLE exists, skip to avoid breaking local intentional disable.
        if FileManager.default.fileExists(atPath: SafetyRails.killSwitchURL.path) {
            throw XCTSkip("Kill switch present at ~/.rootstock-red/DISABLE")
        }
        try SafetyRails.ensureNotDisabled()
    }

    func testRootstockDescribeTriState() {
        XCTAssertEqual(Optional(true).rootstockDescribe, "true")
        XCTAssertEqual(Optional(false).rootstockDescribe, "false")
        let unknown: Bool? = nil
        XCTAssertEqual(unknown.rootstockDescribe, "unknown")
    }

    func testProcessRunnerBlockedInAssess() {
        let runner = ProcessRunner.forContext(.assess())
        XCTAssertThrowsError(try runner.run(executable: "/bin/echo")) { error in
            XCTAssertEqual(error as? RootstockError, .processNotAllowedInAssess)
        }
    }

    func testSchemaVersion() {
        XCTAssertEqual(RootstockCore.schemaVersion, "1.0.0")
    }

    func testAuditLogAppendWritesJSONL() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("rootstock-audit-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let auditURL = try AuditLog.defaultURL(projectDirectory: dir)
        XCTAssertEqual(auditURL.lastPathComponent, "audit.jsonl")

        let audit = AuditLog(fileURL: auditURL)
        let record = AuditRecord(
            run: .init(mode: .assess, profile: .standard, allowNetwork: false),
            subject: .init(
                operatorName: "test-operator",
                scope: "ENG-TEST",
                hostUUID: "host-uuid-1",
                argvSummary: "rootstock-red audit --profile standard"
            ),
            outcome: .init(
                findingCount: 3,
                collectorIds: ["collect.host"],
                checkIds: ["rootstock.check.host.identity"]
            )
        )
        try await audit.append(record)
        try await audit.append(record)

        let text = try String(contentsOf: auditURL, encoding: .utf8)
        let lines = text.split(whereSeparator: \.isNewline).map(String.init)
        XCTAssertEqual(lines.count, 2)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        for line in lines {
            let decoded = try decoder.decode(AuditRecord.self, from: Data(line.utf8))
            XCTAssertEqual(decoded.mode, .assess)
            XCTAssertEqual(decoded.profile, .standard)
            XCTAssertEqual(decoded.operatorName, "test-operator")
            XCTAssertEqual(decoded.scope, "ENG-TEST")
            XCTAssertEqual(decoded.hostUUID, "host-uuid-1")
            XCTAssertEqual(decoded.findingCount, 3)
            XCTAssertEqual(decoded.collectorIds, ["collect.host"])
            XCTAssertEqual(decoded.checkIds, ["rootstock.check.host.identity"])
            XCTAssertFalse(decoded.allowNetwork)
            XCTAssertEqual(decoded.schemaVersion, RootstockCore.schemaVersion)
        }
        XCTAssertEqual(audit.fileURL, auditURL)
    }
}
