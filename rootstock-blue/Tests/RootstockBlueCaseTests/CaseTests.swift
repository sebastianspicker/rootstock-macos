import XCTest
@testable import RootstockBlueCase
@testable import RootstockBlueCore

final class CaseTests: XCTestCase {
    func testCreateOpenVerify() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("rootstock-blue-test-\(UUID().uuidString).rsbcase")
        defer { try? FileManager.default.removeItem(at: tmp) }

        let created = try CasePackage.create(at: tmp, name: "unit-test")
        XCTAssertEqual(created.manifest.name, "unit-test")
        try created.verifyLayout()

        let env = EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "NOTIFY_EXEC",
                label: "test"
            ),
            capture: EventEnvelope.Capture(
                source: .es
            ),
            payload: EventEnvelope.Payload(
                properties: [FieldTaxonomy.processPath: "/usr/bin/true"]
            )
        )
        try created.appendEventJSONL(env)
        try created.appendCustody(CustodyEvent(actor: "test", action: "note", detail: "hello"))

        let opened = try CasePackage.open(at: tmp)
        XCTAssertEqual(opened.manifest.caseID, created.manifest.caseID)

        let db = try opened.openDatabase()
        let version = try db.queryScalar("SELECT value FROM schema_meta WHERE key='version';")
        XCTAssertEqual(version, "0")
    }

    func testDuplicateCreateFails() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("rootstock-blue-dup-\(UUID().uuidString).rsbcase")
        defer { try? FileManager.default.removeItem(at: tmp) }
        _ = try CasePackage.create(at: tmp)
        XCTAssertThrowsError(try CasePackage.create(at: tmp))
    }

    /// Proves timeline + custody writes go through real `CaseDatabase` bound-parameter APIs
    /// (values with quotes must round-trip; not string-spliced SQL).
    func testTimelineAndCustodyBoundParametersRoundTrip() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("rootstock-blue-bind-\(UUID().uuidString).rsbcase")
        defer { try? FileManager.default.removeItem(at: tmp) }

        let pkg = try CasePackage.create(at: tmp, name: "bind-test")
        let evilSummaryPath = "/Users/o'brian/bin/evil's tool"
        let env = EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "NOTIFY_EXEC",
                label: "test'plugin"
            ),
            capture: EventEnvelope.Capture(
                source: .es
            ),
            payload: EventEnvelope.Payload(
                properties: [FieldTaxonomy.processPath: evilSummaryPath]
            )
        )
        try pkg.insertTimelineEvent(env)
        try pkg.appendCustody(
            CustodyEvent(actor: "alice'bob", action: "note", detail: "detail with ' quotes")
        )

        let db = try pkg.openDatabase()
        let rows = try db.queryRows(
            "SELECT summary, source_plugin FROM timeline_events WHERE id = ?;",
            bindings: [.text(env.id.uuidString)]
        )
        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(rows[0]["summary"], evilSummaryPath)
        XCTAssertEqual(rows[0]["source_plugin"], "test'plugin")

        let custody = try db.queryRows(
            "SELECT actor, action, detail FROM custody_events WHERE actor = ?;",
            bindings: [.text("alice'bob")]
        )
        XCTAssertEqual(custody.count, 1)
        XCTAssertEqual(custody[0]["detail"], "detail with ' quotes")
        XCTAssertEqual(custody[0]["action"], "note")
    }
}
