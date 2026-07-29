import XCTest
@testable import RootstockBlueDetect
@testable import RootstockBlueCore

final class DetectTests: XCTestCase {
    func testFixtureRunnerMatches() throws {
        let rule = DetectionRule(
            id: "test.unsigned_exec",
            title: "Unsigned exec",
            severity: "high",
            description: "test",
            attackTechniques: ["T1204"],
            match: .init(
                eventType: "NOTIFY_EXEC",
                fieldEquals: [FieldTaxonomy.processSigned: "false"]
            ),
            fixture: "unsigned_exec.jsonl"
        )
        let event = EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "NOTIFY_EXEC",
                label: "test"
            ),
            capture: EventEnvelope.Capture(
                source: .es
            ),
            payload: EventEnvelope.Payload(
                properties: [
                FieldTaxonomy.processPath: "/tmp/evil",
                FieldTaxonomy.processSigned: "false",
            ]
            )
        )
        let findings = FixtureRunner.evaluate(rule: rule, events: [event])
        XCTAssertEqual(findings.count, 1)
        XCTAssertEqual(findings[0].ruleID, "test.unsigned_exec")
    }

    func testSampleContentIfPresent() throws {
        // Prefer repo Content/ when running from package root.
        let cwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        let rulesDir = cwd.appendingPathComponent("Content/detections/samples")
        let fixturesDir = rulesDir.appendingPathComponent("fixtures")
        guard FileManager.default.fileExists(atPath: rulesDir.path) else {
            throw XCTSkip("Content/detections/samples not found from \(cwd.path)")
        }
        let rules = try RuleLoader.loadDirectory(rulesDir)
        XCTAssertFalse(rules.isEmpty, "expected sample rules under \(rulesDir.path)")
        for rule in rules {
            XCTAssertNotNil(rule.match.eventType, "rule \(rule.id) missing event_type")
            let fixtureURL = fixturesDir.appendingPathComponent(rule.fixture)
            let events = try FixtureRunner.loadEvents(from: fixtureURL)
            XCTAssertFalse(events.isEmpty, "fixture empty for \(rule.fixture)")
            let findings = FixtureRunner.evaluate(rule: rule, events: events)
            XCTAssertFalse(findings.isEmpty, "rule \(rule.id) produced no findings; fields=\(events.first?.fields ?? [:]) matchEq=\(rule.match.fieldEquals ?? [:])")
        }
        let engine = DetectionEngine()
        let findings = try engine.run(rulesDirectory: rulesDir, fixturesDirectory: fixturesDir)
        XCTAssertGreaterThanOrEqual(findings.count, 1)
    }
}
