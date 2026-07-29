import XCTest
@testable import RootstockBlueESKit
@testable import RootstockBlueCore
@testable import RootstockBlueCase

final class ESKitTests: XCTestCase {
    func testMockClientAndMute() throws {
        let client = MockESClient()
        let profile = ESSubscriptionProfile.builtin(.quiet)
        XCTAssertFalse(profile.authMode)
        try client.start(profile: profile)
        client.injectRaw([
            [
                "event_type": "NOTIFY_EXEC",
                FieldTaxonomy.processPath: "/bin/echo",
                FieldTaxonomy.processPid: "99",
            ]
        ])
        let events = client.pollEvents()
        XCTAssertEqual(events.count, 1)
        XCTAssertEqual(events[0].eventType, "NOTIFY_EXEC")
        XCTAssertGreaterThan(client.counters.mapped, 0)
        client.stop()
    }

    func testRingBufferDropsCounted() {
        let buf = RingBuffer<Int>(capacity: 2)
        XCTAssertTrue(buf.enqueue(1))
        XCTAssertTrue(buf.enqueue(2))
        XCTAssertFalse(buf.enqueue(3))
        let c = buf.snapshotCounters()
        XCTAssertEqual(c.droppedBackpressure, 1)
        XCTAssertEqual(c.enqueued, 2)
        XCTAssertEqual(c.received, 3)
    }

    /// Concurrent producers against the real `RingBuffer` lock path - drops still counted, never silent.
    func testRingBufferConcurrentDropsCounted() {
        let capacity = 64
        let buf = RingBuffer<Int>(capacity: capacity)
        let total = 2_000
        let group = DispatchGroup()
        let queue = DispatchQueue(label: "ringbuffer.stress", attributes: .concurrent)
        for i in 0..<total {
            group.enter()
            queue.async {
                _ = buf.enqueue(i)
                group.leave()
            }
        }
        group.wait()
        let c = buf.snapshotCounters()
        XCTAssertEqual(c.received, UInt64(total))
        XCTAssertEqual(c.enqueued + c.droppedBackpressure, UInt64(total))
        XCTAssertEqual(c.enqueued, UInt64(capacity))
        XCTAssertEqual(c.droppedBackpressure, UInt64(total - capacity))
        XCTAssertEqual(buf.dequeueAll().count, capacity)
    }

    func testMutePolicy() {
        let policy = MutePolicy(pathPrefixes: ["/System/"])
        XCTAssertTrue(policy.shouldMute(path: "/System/Library/foo"))
        XCTAssertFalse(policy.shouldMute(path: "/Users/me/bin"))
    }

    func testProfilesAuthOff() {
        for name in ESProfileName.allCases {
            XCTAssertFalse(ESSubscriptionProfile.builtin(name).authMode)
        }
    }

    func testSessionRecorderWritesCase() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("cf-session-\(UUID().uuidString).rsbcase")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let pkg = try CasePackage.create(at: tmp, name: "session-test")
        let sink = CaseEventSink(package: pkg)
        let recorder = SessionRecorder(profile: .builtin(.ir))
        let client = MockESClient()
        let result = try recorder.recordInjected(
            raw: [
                [
                    "event_type": "NOTIFY_EXEC",
                    FieldTaxonomy.processPath: "/tmp/evil",
                    FieldTaxonomy.processPid: "7",
                    FieldTaxonomy.processSigned: "false",
                ]
            ],
            client: client,
            into: sink
        )
        XCTAssertEqual(result.written, 1)
        XCTAssertGreaterThan(result.counters.mapped, 0)
        let events = try pkg.loadAllEvents()
        XCTAssertEqual(events.count, 1)
        XCTAssertEqual(events[0].eventType, "NOTIFY_EXEC")
        let db = try pkg.openDatabase()
        let rows = try db.queryRows("SELECT COUNT(*) AS c FROM timeline_events;")
        XCTAssertEqual(rows.first?["c"], "1")
    }

    func testLoadEnvelopesFromFixtureJSONL() throws {
        let url = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("Fixtures/es/session_inject.jsonl")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: url.path))
        let events = try SessionRecorder.loadEnvelopes(fromJSONL: url)
        XCTAssertGreaterThanOrEqual(events.count, 3)
    }
}
