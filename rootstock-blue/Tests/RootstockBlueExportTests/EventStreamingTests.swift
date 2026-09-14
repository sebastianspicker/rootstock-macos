import Foundation
import XCTest
@testable import RootstockBlueCase
@testable import RootstockBlueCore

final class EventStreamingTests: XCTestCase {
    func testEventSinkBatchRequirementDispatchesThroughExistentialAndFallback() throws {
        let first = streamingSampleEvent()
        let second = streamingSampleEvent(id: "D5EA2CEF-5D6A-4206-ABCB-74DCFA1AC779")
        let fallback = SingleEventSink()
        let fallbackExistential: any EventSink = fallback

        try fallbackExistential.append(
            [first, second],
            custody: EventCustodyNote(action: "fixture", detail: "two")
        )
        XCTAssertEqual(fallback.eventIDs, [first.id, second.id])
        XCTAssertEqual(fallback.custodyNotes, [EventCustodyNote(action: "fixture", detail: "two")])

        let batch = BatchAwareEventSink()
        let batchExistential: any EventSink = batch
        try batchExistential.append([first, second], custody: nil)
        XCTAssertEqual(batch.batchCalls, 1)
        XCTAssertEqual(batch.eventIDs, [first.id, second.id])
        XCTAssertEqual(batch.singleCalls, 0)
    }

    func testEventSinkFallbackHandlesEmptyAndCustodyOnlyBatches() throws {
        let sink = SingleEventSink()
        let existential: any EventSink = sink
        try existential.append([], custody: nil)
        XCTAssertTrue(sink.eventIDs.isEmpty)
        XCTAssertTrue(sink.custodyNotes.isEmpty)

        try existential.append([], custody: EventCustodyNote(action: "empty", detail: "custody only"))
        XCTAssertTrue(sink.eventIDs.isEmpty)
        XCTAssertEqual(sink.custodyNotes, [EventCustodyNote(action: "empty", detail: "custody only")])
    }

    func testStreamingJSONLAcceptsEveryUnicodeNewlineAndPartialFinalRecord() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let url = scratch.appendingPathComponent("events.jsonl")
        let events = (0..<7).map { index in
            streamingSampleEvent(id: String(format: "00000000-0000-4000-8000-%012d", index))
        }
        let separators = ["\n", "\u{000B}", "\u{000C}", "\r", "\u{0085}", "\u{2028}", "\u{2029}"]
        let records = try events.map { event -> String in
            let line = try EventJSONL.encodeLine(event)
            return String(decoding: line.dropLast(), as: UTF8.self)
        }
        let text = zip(records, separators).map { " \t\($0.0)\t \($0.1)" }.joined()
            + records.last!
        try Data(text.utf8).write(to: url)

        var streamed: [UUID] = []
        try EventJSONL.forEach(contentsOf: url) { streamed.append($0.id) }
        XCTAssertEqual(streamed, events.map(\.id) + [events.last!.id])
        XCTAssertEqual(try EventJSONL.decode(contentsOf: url).map(\.id), streamed)
    }

    func testStreamingJSONLHandlesUTF8ScalarAcrossChunkBoundaryAndRejectsInvalidUTF8() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let splitURL = scratch.appendingPathComponent("split.jsonl")
        var bytes = Data(repeating: 0x20, count: JSONLRecordReader.chunkSize - 1)
        bytes.append(contentsOf: "😀\ntail".utf8)
        try bytes.write(to: splitURL)
        var records: [String] = []
        try JSONLRecordReader.forEachRecord(contentsOf: splitURL) {
            records.append(try JSONLRecordReader.strictUTF8($0))
        }
        XCTAssertEqual(records.count, 2)
        XCTAssertTrue(records[0].hasSuffix("😀"))
        XCTAssertEqual(records[1], "tail")

        let invalidURL = scratch.appendingPathComponent("invalid.jsonl")
        try Data([0x7B, 0xFF, 0x7D, 0x0A]).write(to: invalidURL)
        XCTAssertThrowsError(try EventJSONL.forEach(contentsOf: invalidURL, skipInvalid: true) { _ in })
    }

    func testStreamingJSONLSkipInvalidDoesNotConsumeCallbackErrors() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let url = scratch.appendingPathComponent("callback.jsonl")
        try EventJSONL.encode([streamingSampleEvent()]).write(to: url)

        XCTAssertThrowsError(
            try EventJSONL.forEach(contentsOf: url, skipInvalid: true) { _ in
                throw StreamingFixtureError.callback
            }
        ) { error in
            XCTAssertEqual(error as? StreamingFixtureError, .callback)
        }
    }

    func testStreamingJSONLSkipInvalidSkipsMalformedJSONRecords() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let url = scratch.appendingPathComponent("skip-invalid.jsonl")
        let first = streamingSampleEvent()
        let second = streamingSampleEvent(id: "70000000-0000-4000-8000-000000000001")
        var data = try EventJSONL.encodeLine(first)
        data.append(contentsOf: "{malformed}\n".utf8)
        data.append(try EventJSONL.encodeLine(second))
        try data.write(to: url)

        var streamed: [UUID] = []
        try EventJSONL.forEach(contentsOf: url, skipInvalid: true) { streamed.append($0.id) }
        XCTAssertEqual(streamed, [first.id, second.id])
        XCTAssertThrowsError(try EventJSONL.forEach(contentsOf: url) { _ in })
    }

    func testSequenceWriterConsumesLazyEventsOneLineAtATime() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let url = scratch.appendingPathComponent("lazy.jsonl")
        XCTAssertTrue(FileManager.default.createFile(atPath: url.path, contents: nil))
        let handle = try FileHandle(forWritingTo: url)
        defer { try? handle.close() }
        var produced: [Int] = []
        let events = (0..<3).lazy.map { index -> EventEnvelope in
            produced.append(index)
            return streamingSampleEvent(
                id: String(format: "60000000-0000-4000-8000-%012d", index)
            )
        }

        let count = try EventJSONL.write(sequence: events, to: handle)
        XCTAssertEqual(count, 3)
        XCTAssertEqual(produced, [0, 1, 2])
        try handle.close()
        XCTAssertEqual(try EventJSONL.decode(contentsOf: url).count, 3)
    }

    func testBatchOfOneThousandUsesOneIntegrityAndChecksumCycle() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let package = try CasePackage.create(at: scratch.appendingPathComponent("case.rsbcase"))
        let events = (0..<1_000).map { index in
            streamingSampleEvent(id: String(format: "10000000-0000-4000-8000-%012d", index))
        }
        var integrityChecks = 0
        var checksumWrites = 0
        try package.appendEventBatch(
            events,
            stream: "es",
            custody: CustodyEvent(actor: "fixture", action: "bulk"),
            afterEventWrite: nil,
            afterIntegrityCheck: { integrityChecks += 1 },
            afterHashManifestWrite: { checksumWrites += 1 }
        )

        XCTAssertEqual(integrityChecks, 1)
        XCTAssertEqual(checksumWrites, 1)
        XCTAssertEqual(try package.loadAllEvents().count, 1_000)
        XCTAssertEqual(try CustodyLog.decode(contentsOf: package.custodyURL).filter { $0.action == "bulk" }.count, 1)
        XCTAssertNoThrow(try package.verifyIntegrity())
    }

    func testReadonlyProjectionVerificationRejectsMissingAndExtraRowsWithoutChangingDatabaseBytes() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }

        let missing = try CasePackage.create(at: scratch.appendingPathComponent("missing.rsbcase"))
        let event = streamingSampleEvent()
        try missing.appendEvent(event)
        let missingDB = try CaseDatabase(url: missing.databaseURL)
        try missingDB.execute("DELETE FROM timeline_events WHERE id = ?;", bindings: [.text(event.id.uuidString)])
        try missing.writeHashManifest()
        let missingBefore = try Data(contentsOf: missing.databaseURL)
        XCTAssertThrowsError(try missing.verifyIntegrity())
        XCTAssertEqual(try Data(contentsOf: missing.databaseURL), missingBefore)

        let extra = try CasePackage.create(at: scratch.appendingPathComponent("extra.rsbcase"))
        try extra.appendEvent(event)
        let extraDB = try CaseDatabase(url: extra.databaseURL)
        try extraDB.insertTimeline(streamingSampleEvent(id: "20000000-0000-4000-8000-000000000001"))
        try extra.writeHashManifest()
        let extraBefore = try Data(contentsOf: extra.databaseURL)
        XCTAssertThrowsError(try extra.verifyIntegrity())
        XCTAssertEqual(try Data(contentsOf: extra.databaseURL), extraBefore)
    }

    func testOneHundredThousandEventIntegrityWhenExplicitlyRequested() throws {
        guard ProcessInfo.processInfo.environment["ROOTSTOCK_BLUE_RUN_100K_TEST"] == "1" else {
            throw XCTSkip("set ROOTSTOCK_BLUE_RUN_100K_TEST=1 for the bounded-memory verification workload")
        }
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let package = try CasePackage.create(at: scratch.appendingPathComponent("large.rsbcase"))
        var events: [EventEnvelope]? = (0..<100_000).map { index in
            streamingSampleEvent(id: String(format: "30000000-0000-4000-8000-%012d", index))
        }
        try package.appendEventBatch(events!, stream: "es", custody: nil)
        events = nil
        XCTAssertNoThrow(try package.verifyIntegrity())
    }
}

private func streamingSampleEvent(
    id: String = "8EBE8993-8CFF-422E-8E6A-5845D60D42EE"
) -> EventEnvelope {
    let timestamp = ISO8601DateFormatter().date(from: "2026-08-27T12:00:00Z")!
    return EventEnvelope(
        identity: .init(id: UUID(uuidString: id)!, kind: "fixture.event", label: "fixture"),
        capture: .init(source: .synthetic, eventTime: timestamp, collectedAt: timestamp),
        payload: .init(
            entityRefs: [.file(path: "/tmp/synthetic-fixture")],
            properties: [FieldTaxonomy.filePath: "/tmp/synthetic-fixture"]
        )
    )
}

private enum StreamingFixtureError: Error, Equatable {
    case callback
}

private final class SingleEventSink: EventSink, @unchecked Sendable {
    private let lock = NSLock()
    private var storedEventIDs: [UUID] = []
    private var storedCustodyNotes: [EventCustodyNote] = []

    var eventIDs: [UUID] { lock.withLock { storedEventIDs } }
    var custodyNotes: [EventCustodyNote] { lock.withLock { storedCustodyNotes } }

    func append(_ event: EventEnvelope) throws {
        lock.withLock { storedEventIDs.append(event.id) }
    }

    func noteCustody(action: String, detail: String) throws {
        lock.withLock { storedCustodyNotes.append(EventCustodyNote(action: action, detail: detail)) }
    }
}

private final class BatchAwareEventSink: EventSink, @unchecked Sendable {
    private let lock = NSLock()
    private var storedEventIDs: [UUID] = []
    private var storedBatchCalls = 0
    private var storedSingleCalls = 0

    var eventIDs: [UUID] { lock.withLock { storedEventIDs } }
    var batchCalls: Int { lock.withLock { storedBatchCalls } }
    var singleCalls: Int { lock.withLock { storedSingleCalls } }

    func append(_ event: EventEnvelope) throws {
        lock.withLock {
            storedSingleCalls += 1
            storedEventIDs.append(event.id)
        }
    }

    func append(_ events: [EventEnvelope], custody: EventCustodyNote?) throws {
        lock.withLock {
            storedBatchCalls += 1
            storedEventIDs.append(contentsOf: events.map(\.id))
        }
    }

    func noteCustody(action: String, detail: String) throws {}
}
