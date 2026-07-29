import XCTest
@testable import RootstockBlueCore

final class CoreTests: XCTestCase {
    func testProductModeAuthNeverDefault() {
        for mode in ProductMode.allCases {
            XCTAssertFalse(mode.authBlockingDefault)
        }
        XCTAssertFalse(NonGoals.authBlockDefaultOn)
    }

    func testEntityID() {
        let p = EntityID.process(pid: 42, path: "/bin/zsh")
        XCTAssertEqual(p.kind, .process)
        XCTAssertTrue(p.value.contains("pid=42"))
    }

    func testLossCounters() {
        var c = LossCounters()
        c.recordReceived()
        c.recordEnqueued()
        c.recordDroppedBackpressure()
        XCTAssertEqual(c.received, 1)
        XCTAssertEqual(c.enqueued, 1)
        XCTAssertEqual(c.totalDropped, 1)
    }

    func testEventEnvelopeCodable() throws {
        let e = EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "NOTIFY_EXEC",
                label: "test"
            ),
            capture: EventEnvelope.Capture(
                source: .es
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [.process(pid: 1, path: "/bin/ls")],
                properties: [FieldTaxonomy.processPath: "/bin/ls"]
            )
        )
        let data = try JSONEncoder().encode(e)
        let decoded = try JSONDecoder().decode(EventEnvelope.self, from: data)
        XCTAssertEqual(decoded.eventType, "NOTIFY_EXEC")
        XCTAssertEqual(decoded.fields[FieldTaxonomy.processPath], "/bin/ls")
    }

    func testEventJSONLRoundTrip() throws {
        let e = EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "NOTIFY_EXEC",
                label: "test"
            ),
            capture: EventEnvelope.Capture(
                source: .es
            ),
            payload: EventEnvelope.Payload(
                properties: [FieldTaxonomy.processPath: "/bin/ls"]
            )
        )
        let data = try EventJSONL.encode([e])
        let text = String(data: data, encoding: .utf8)!
        let decoded = try EventJSONL.decode(text: text)
        XCTAssertEqual(decoded.count, 1)
        XCTAssertEqual(decoded[0].eventType, "NOTIFY_EXEC")
        XCTAssertEqual(decoded[0].fields[FieldTaxonomy.processPath], "/bin/ls")
    }

    func testEventJSONLSkipInvalid() throws {
        let good = EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "x",
                label: "t"
            ),
            capture: EventEnvelope.Capture(
                source: .synthetic
            ),
            payload: EventEnvelope.Payload(

            )
        )
        let line = try EventJSONL.encodeLine(good)
        let mixed = String(data: line, encoding: .utf8)! + "{not-json}\n"
        let skipped = try EventJSONL.decode(text: mixed, skipInvalid: true)
        XCTAssertEqual(skipped.count, 1)
        XCTAssertThrowsError(try EventJSONL.decode(text: mixed, skipInvalid: false))
    }
}
