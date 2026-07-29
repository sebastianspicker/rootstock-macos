import XCTest
@testable import RootstockBlueExport
@testable import RootstockBlueCase
@testable import RootstockBlueFX
@testable import RootstockBlueCore
@testable import RootstockBlueDetect

final class CaseReportTests: XCTestCase {
    func testMarkdownReportHasConcreteStats() throws {
        let fixture = URL(fileURLWithPath: "Fixtures/artifacts/macos_sample")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: fixture.path))

        let scratch = FileManager.default.temporaryDirectory
            .appendingPathComponent("report-case-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: scratch) }

        let caseURL = scratch.appendingPathComponent("incident.rsbcase")
        let pkg = try CasePackage.create(at: caseURL, name: "report-test")
        let n = try ForensicsEngine().parse(source: .directory(fixture), into: pkg)
        XCTAssertGreaterThan(n, 5)

        let rulesDir = URL(fileURLWithPath: "Content/detections/samples")
        let events = try CaseTimeline.merged(from: pkg)
        let findings = FileManager.default.fileExists(atPath: rulesDir.path)
            ? try DetectionEngine().evaluate(rulesDirectory: rulesDir, events: events)
            : []

        let out = scratch.appendingPathComponent("case-report.md")
        let stats = try CaseReport.exportMarkdown(package: pkg, to: out, findings: findings)
        XCTAssertGreaterThan(stats.eventCount, 0)
        XCTAssertFalse(stats.byPlugin.isEmpty)
        XCTAssertGreaterThan(stats.custodyLines, 0)

        let body = try String(contentsOf: out, encoding: .utf8)
        XCTAssertFalse(body.isEmpty)
        XCTAssertTrue(body.contains("IR Case Report"), "not a stub string")
        XCTAssertTrue(body.contains("Timeline events:"))
        XCTAssertTrue(body.contains("Events by source plugin"))
        // Plugin table should mention known parsers
        XCTAssertTrue(
            body.contains("TCC") || body.contains("BASICINFO") || body.contains("SAFARI"),
            "report must list real plugins"
        )
        XCTAssertTrue(body.contains(String(stats.eventCount)))
    }
}
