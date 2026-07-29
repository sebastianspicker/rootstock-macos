import XCTest
@testable import RootstockBlueFX
@testable import RootstockBlueCore

/// Post-incident DFIR parsers - drive shipped code on fixture trees.
final class ForensicsDFIRTests: XCTestCase {
    var relativeRoot: URL {
        URL(fileURLWithPath: "Fixtures/artifacts/macos_sample")
    }

    var absoluteRoot: URL {
        relativeRoot.standardizedFileURL.resolvingSymlinksInPath()
    }

    func testSafariParserEmitsVisitsAndDownloads() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try SafariParser().parse(source: .directory(relativeRoot))
        let visits = events.filter { $0.eventType == "browser.visit" }
        let downloads = events.filter { $0.eventType == "browser.download" }
        XCTAssertGreaterThanOrEqual(visits.count, 1, "Safari visits must be non-empty")
        XCTAssertGreaterThanOrEqual(downloads.count, 1, "Safari downloads must be non-empty")
        XCTAssertTrue(visits.contains { ($0.fields["browser.url"] ?? "").contains("evil.example") })
        XCTAssertTrue(visits.allSatisfy { $0.sourcePlugin == "SAFARI" })
        XCTAssertFalse(visits[0].entityRefs.isEmpty)
    }

    func testChromiumParserEmitsVisitsAndDownloads() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try ChromiumParser().parse(source: .directory(relativeRoot))
        let visits = events.filter { $0.eventType == "browser.visit" }
        let downloads = events.filter { $0.eventType == "browser.download" }
        XCTAssertGreaterThanOrEqual(visits.count, 1)
        XCTAssertGreaterThanOrEqual(downloads.count, 1)
        XCTAssertTrue(visits.contains { ($0.fields["browser.url"] ?? "").contains("evil.example") })
        XCTAssertEqual(events.first?.fields["browser.engine"], "chrome")
    }

    func testKnowledgeCParserEmitsAppUsage() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try KnowledgeCParser().parse(source: .directory(relativeRoot))
        XCTAssertGreaterThanOrEqual(events.count, 1)
        XCTAssertTrue(events.contains { $0.eventType == "pol.app_usage" })
        XCTAssertTrue(events.contains { ($0.fields["pol.value"] ?? "").contains("Safari")
            || ($0.fields["pol.value"] ?? "").contains("Chrome")
            || ($0.fields["pol.value"] ?? "").contains("Terminal") })
    }

    func testRecentItemsParserEmitsMRU() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try RecentItemsParser().parse(source: .directory(relativeRoot))
        XCTAssertGreaterThanOrEqual(events.count, 1)
        XCTAssertTrue(events.contains { $0.eventType == "mru.document" })
        XCTAssertTrue(events.contains { ($0.fields["mru.name"] ?? "").contains("secrets")
            || ($0.fields["mru.path"] ?? "").contains("Documents") })
    }

    func testFullEngineRelativeAbsoluteParityAndNewParsers() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let engine = ForensicsEngine()
        let rel = try engine.parse(source: ImageSource.infer(from: relativeRoot))
        let abs = try engine.parse(source: ImageSource.infer(from: absoluteRoot))
        XCTAssertEqual(rel.count, abs.count, "relative/absolute must not double-count")

        let plugins = Set(rel.map(\.sourcePlugin))
        for id in ["SAFARI", "CHROMIUM", "KNOWLEDGEC", "RECENTITEMS", "TCC"] {
            XCTAssertTrue(plugins.contains(id), "missing plugin \(id) in engine output")
        }

        let tccRel = try TCCParser().parse(source: .directory(relativeRoot))
        let tccAbs = try TCCParser().parse(source: .directory(absoluteRoot))
        XCTAssertEqual(tccRel.count, tccAbs.count)
        XCTAssertEqual(tccRel.count, 4)
    }

    func testChromeEpochConversionSane() {
        // 13351305600000000 ≈ 2024-01-01 Chrome epoch µs
        let d = Epochs.dateFromChromeMicroseconds(13_351_305_600_000_000)
        let year = Calendar(identifier: .gregorian).component(.year, from: d)
        XCTAssertEqual(year, 2024)
    }
}
