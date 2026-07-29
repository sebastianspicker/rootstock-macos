import XCTest
@testable import RootstockBlueFX
@testable import RootstockBlueCore

final class FXTests: XCTestCase {
    var fixtureRoot: URL {
        URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("Fixtures/artifacts/macos_sample")
    }

    func testTier1ParsersRegistered() {
        let runtime = PluginRuntime()
        let ids = Set(runtime.parserIDs())
        for id in [
            "TCC", "QUARANTINE", "AUTOSTART", "USERS", "FSEVENTS", "TERMSESSIONS", "XPROTECT",
            "BASICINFO", "INSTALLHISTORY", "DOCK",
        ] {
            XCTAssertTrue(ids.contains(id), "missing \(id)")
        }
    }

    func testTimelineMergeOrderAndEntities() {
        let a = EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "tcc.access",
                label: "TCC"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: Date(timeIntervalSince1970: 100)
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .tcc, value: "cam|app")]
            )
        )
        let b = EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "NOTIFY_EXEC",
                label: "eskit"
            ),
            capture: EventEnvelope.Capture(
                source: .es,
                eventTime: Date(timeIntervalSince1970: 50)
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [.process(pid: 1, path: "/bin/zsh")]
            )
        )
        let merged = TimelineMerger.merge([a, b])
        XCTAssertEqual(merged.map(\.eventType), ["NOTIFY_EXEC", "tcc.access"])
        XCTAssertFalse(merged[0].entityRefs.isEmpty)
        XCTAssertFalse(merged[1].entityRefs.isEmpty)
    }

    func testTCCParserEmitsEvents() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: fixtureRoot.path), "fixture tree missing")
        let events = try TCCParser().parse(source: .directory(fixtureRoot))
        XCTAssertGreaterThanOrEqual(events.count, 4)
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "TCC" })
        XCTAssertTrue(events.contains { $0.fields[FieldTaxonomy.tccService]?.contains("SystemPolicyAllFiles") == true })
        XCTAssertTrue(events.allSatisfy { !$0.entityRefs.isEmpty })
    }

    func testQuarantineParserEmitsEvents() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: fixtureRoot.path), "fixture tree missing")
        let events = try QuarantineParser().parse(source: .directory(fixtureRoot))
        XCTAssertGreaterThanOrEqual(events.count, 2)
        XCTAssertTrue(events.contains { ($0.fields["quarantine.origin_url"] ?? "").contains("evil.example") })
    }

    func testAutostartParserEmitsEvents() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: fixtureRoot.path), "fixture tree missing")
        let events = try AutostartParser().parse(source: .directory(fixtureRoot))
        XCTAssertGreaterThanOrEqual(events.count, 3)
        XCTAssertTrue(events.contains { $0.fields["persistence.label"] == "com.example.persist" })
        XCTAssertTrue(events.allSatisfy { $0.entityRefs.contains { $0.kind == .persistence } })
    }

    func testUsersParserEmitsEvents() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: fixtureRoot.path), "fixture tree missing")
        let events = try UsersParser().parse(source: .directory(fixtureRoot))
        XCTAssertGreaterThanOrEqual(events.count, 3)
        let names = Set(events.compactMap { $0.fields[FieldTaxonomy.userName] })
        XCTAssertTrue(names.contains("alice"))
        XCTAssertTrue(names.contains("bob"))
    }

    func testForensicsEngineNonEmptyOnFixtureTree() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: fixtureRoot.path), "fixture tree missing")
        let engine = ForensicsEngine()
        let events = try engine.parse(source: .directory(fixtureRoot))
        XCTAssertGreaterThan(events.count, 10, "expected multi-parser non-empty timeline")
        let plugins = Set(events.map(\.sourcePlugin))
        XCTAssertTrue(plugins.contains("TCC"))
        XCTAssertTrue(plugins.contains("QUARANTINE"))
        XCTAssertTrue(plugins.contains("AUTOSTART"))
        XCTAssertTrue(plugins.contains("USERS"))
    }

    /// Relative roots (README/CLI style) must not double-parse the same DB.
    func testRelativeRootDoesNotDoubleParseTCCOrQuarantine() throws {
        let relative = URL(fileURLWithPath: "Fixtures/artifacts/macos_sample")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relative.path), "relative fixture missing")
        let absolute = relative.standardizedFileURL.resolvingSymlinksInPath()

        let tccRel = try TCCParser().parse(source: .directory(relative))
        let tccAbs = try TCCParser().parse(source: .directory(absolute))
        XCTAssertEqual(tccRel.count, tccAbs.count, "TCC count must match relative vs absolute root")
        XCTAssertEqual(tccRel.count, 4, "fixture TCC.db has 4 access rows")

        let qRel = try QuarantineParser().parse(source: .directory(relative))
        let qAbs = try QuarantineParser().parse(source: .directory(absolute))
        XCTAssertEqual(qRel.count, qAbs.count)
        XCTAssertEqual(qRel.count, 2)

        let engine = ForensicsEngine()
        let fullRel = try engine.parse(source: ImageSource.infer(from: relative))
        let fullAbs = try engine.parse(source: ImageSource.infer(from: absolute))
        XCTAssertEqual(fullRel.count, fullAbs.count, "full engine must not double-count on relative roots")
    }

    func testHiddenArtifactsTerminalAndFSEvents() throws {
        let relative = URL(fileURLWithPath: "Fixtures/artifacts/macos_sample")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relative.path))

        let term = try TerminalParser().parse(source: .directory(relative))
        XCTAssertFalse(term.isEmpty, "TerminalParser must see .zsh_history under Users (hidden path)")
        XCTAssertTrue(term.contains { ($0.fields["shell.command"] ?? "").contains("evil.example") })

        let fsev = try FSEventsParser().parse(source: .directory(relative))
        XCTAssertFalse(fsev.isEmpty, "FSEventsParser must see .fseventsd/export.jsonl")
        XCTAssertTrue(fsev.contains { ($0.fields[FieldTaxonomy.filePath] ?? "").contains("payload.dmg") })
    }

    func testPathKeyStableAcrossRelativeAbsolute() {
        let rel = URL(fileURLWithPath: "Fixtures/artifacts/macos_sample/Library/Application Support/com.apple.TCC/TCC.db")
        let abs = rel.standardizedFileURL.resolvingSymlinksInPath()
        // When both exist, path keys for the same file must compare equal after resolve.
        if FileManager.default.fileExists(atPath: rel.path) {
            XCTAssertEqual(
                ArtifactRoot.pathKey(rel),
                ArtifactRoot.pathKey(abs)
            )
        }
    }
}
