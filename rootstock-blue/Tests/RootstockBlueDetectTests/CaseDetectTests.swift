import XCTest
@testable import RootstockBlueDetect
@testable import RootstockBlueCore
@testable import RootstockBlueFX
@testable import RootstockBlueCase

final class CaseDetectTests: XCTestCase {
    func testAtLeastTenSampleRulesLoadWithFindings() throws {
        let cwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        let rulesDir = cwd.appendingPathComponent("Content/detections/samples")
        let fixturesDir = rulesDir.appendingPathComponent("fixtures")
        guard FileManager.default.fileExists(atPath: rulesDir.path) else {
            throw XCTSkip("Content/detections/samples not found")
        }
        let rules = try RuleLoader.loadDirectory(rulesDir)
        XCTAssertGreaterThanOrEqual(rules.count, 10, "expected ≥10 detection rules, got \(rules.count)")
        let withAttack = rules.filter { !$0.attackTechniques.isEmpty }
        XCTAssertGreaterThanOrEqual(withAttack.count, 5, "ATT&CK tags expected on most rules")

        let engine = DetectionEngine()
        let findings = try engine.run(rulesDirectory: rulesDir, fixturesDirectory: fixturesDir)
        XCTAssertGreaterThanOrEqual(findings.count, 10)

        // Content-correct for at least two known rules
        XCTAssertTrue(findings.contains { $0.ruleID == "sample.unsigned_exec" && $0.severity == "high" })
        XCTAssertTrue(findings.contains { $0.ruleID == "sample.shell_curl_pipe" })
        XCTAssertTrue(findings.contains { $0.title.lowercased().contains("unsigned")
            || $0.title.lowercased().contains("curl") })
    }

    func testCaseTimelineEvaluationPath() throws {
        let fixture = URL(fileURLWithPath: "Fixtures/artifacts/macos_sample")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: fixture.path))
        let cwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        let rulesDir = cwd.appendingPathComponent("Content/detections/samples")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: rulesDir.path))

        let scratch = FileManager.default.temporaryDirectory
            .appendingPathComponent("detect-case-\(UUID().uuidString).rsbcase")
        defer { try? FileManager.default.removeItem(at: scratch) }
        let pkg = try CasePackage.create(at: scratch, name: "detect-case")
        let engine = ForensicsEngine()
        let n = try engine.parse(source: .directory(fixture), into: pkg)
        XCTAssertGreaterThan(n, 0)

        let events = try CaseTimeline.merged(from: pkg)
        XCTAssertFalse(events.isEmpty)

        let detect = DetectionEngine()
        let findings = try detect.evaluate(rulesDirectory: rulesDir, events: events)
        // Case-backed eval must produce content-correct hits from real parse output
        XCTAssertTrue(
            findings.contains { $0.ruleID == "sample.browser_evil_domain" }
                || findings.contains { $0.ruleID == "sample.shell_curl_pipe" }
                || findings.contains { $0.ruleID == "sample.install_suspicious_pkg" }
                || findings.contains { $0.ruleID == "sample.dock_recent_tmp" }
                || findings.contains { $0.ruleID == "sample.autostart_run_at_load" },
            "case timeline should match ≥1 forensics-derived rule; findings=\(findings.map(\.ruleID))"
        )
        for f in findings.prefix(5) {
            XCTAssertFalse(f.ruleID.isEmpty)
            XCTAssertFalse(f.title.isEmpty)
            XCTAssertFalse(f.severity.isEmpty)
        }
    }
}
