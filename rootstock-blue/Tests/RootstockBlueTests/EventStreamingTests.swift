import Foundation
import Testing
@testable import RootstockBlueCase
@testable import RootstockBlueCore

@Suite struct EventStreamingTests {
    @Test func eventSinkBatchRequirementDispatchesThroughExistentialAndFallback() throws {
        let first = streamingSampleEvent()
        let second = streamingSampleEvent(id: "D5EA2CEF-5D6A-4206-ABCB-74DCFA1AC779")
        let fallback = SingleEventSink()
        let fallbackExistential: any EventSink = fallback

        try fallbackExistential.append(
            [first, second],
            custody: EventCustodyNote(action: "fixture", detail: "two")
        )
        #expect(fallback.eventIDs == [first.id, second.id])
        #expect(fallback.custodyNotes == [EventCustodyNote(action: "fixture", detail: "two")])

        let batch = BatchAwareEventSink()
        let batchExistential: any EventSink = batch
        try batchExistential.append([first, second], custody: nil)
        #expect(batch.batchCalls == 1)
        #expect(batch.eventIDs == [first.id, second.id])
        #expect(batch.singleCalls == 0)
    }

    @Test func eventSinkFallbackHandlesEmptyAndCustodyOnlyBatches() throws {
        let sink = SingleEventSink()
        let existential: any EventSink = sink
        try existential.append([], custody: nil)
        #expect(sink.eventIDs.isEmpty)
        #expect(sink.custodyNotes.isEmpty)

        try existential.append([], custody: EventCustodyNote(action: "empty", detail: "custody only"))
        #expect(sink.eventIDs.isEmpty)
        #expect(sink.custodyNotes == [EventCustodyNote(action: "empty", detail: "custody only")])
    }

    @Test func streamingJSONLAcceptsEveryUnicodeNewlineAndPartialFinalRecord() throws {
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
        #expect(streamed == events.map(\.id) + [events.last!.id])
        #expect(try EventJSONL.decode(contentsOf: url).map(\.id) == streamed)
    }

    @Test func streamingJSONLHandlesUTF8ScalarAcrossChunkBoundaryAndRejectsInvalidUTF8() throws {
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
        #expect(records.count == 2)
        #expect(records[0].hasSuffix("😀"))
        #expect(records[1] == "tail")

        let invalidURL = scratch.appendingPathComponent("invalid.jsonl")
        try Data([0x7B, 0xFF, 0x7D, 0x0A]).write(to: invalidURL)
        #expect(throws: (any Error).self) { try EventJSONL.forEach(contentsOf: invalidURL, skipInvalid: true) { _ in } }
    }

    @Test func streamingJSONLSkipInvalidDoesNotConsumeCallbackErrors() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let url = scratch.appendingPathComponent("callback.jsonl")
        try EventJSONL.encode([streamingSampleEvent()]).write(to: url)

        do {
            _ = try EventJSONL.forEach(contentsOf: url, skipInvalid: true) { _ in
                throw StreamingFixtureError.callback
            }
            Issue.record("Expected error to be thrown")
        } catch {
            #expect(error as? StreamingFixtureError == .callback)
        }
    }

    @Test func streamingJSONLSkipInvalidSkipsMalformedJSONRecords() throws {
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
        #expect(streamed == [first.id, second.id])
        #expect(throws: (any Error).self) { try EventJSONL.forEach(contentsOf: url) { _ in } }
    }

    @Test func sequenceWriterConsumesLazyEventsOneLineAtATime() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let url = scratch.appendingPathComponent("lazy.jsonl")
        #expect(FileManager.default.createFile(atPath: url.path, contents: nil))
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
        #expect(count == 3)
        #expect(produced == [0, 1, 2])
        try handle.close()
        #expect(try EventJSONL.decode(contentsOf: url).count == 3)
    }

    @Test func batchOfOneThousandUsesOneIntegrityAndChecksumCycle() throws {
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

        #expect(integrityChecks == 1)
        #expect(checksumWrites == 1)
        #expect(try package.loadAllEvents().count == 1_000)
        #expect(try CustodyLog.decode(contentsOf: package.custodyURL).filter { $0.action == "bulk" }.count == 1)
        #expect(throws: Never.self) { try package.verifyIntegrity() }
    }

    @Test func readonlyProjectionVerificationRejectsMissingAndExtraRowsWithoutChangingDatabaseBytes() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }

        let missing = try CasePackage.create(at: scratch.appendingPathComponent("missing.rsbcase"))
        let event = streamingSampleEvent()
        try missing.appendEvent(event)
        let missingDB = try CaseDatabase(url: missing.databaseURL)
        try missingDB.execute("DELETE FROM timeline_events WHERE id = ?;", bindings: [.text(event.id.uuidString)])
        try missing.writeHashManifest()
        let missingBefore = try Data(contentsOf: missing.databaseURL)
        #expect(throws: (any Error).self) { try missing.verifyIntegrity() }
        #expect(try Data(contentsOf: missing.databaseURL) == missingBefore)

        let extra = try CasePackage.create(at: scratch.appendingPathComponent("extra.rsbcase"))
        try extra.appendEvent(event)
        let extraDB = try CaseDatabase(url: extra.databaseURL)
        try extraDB.insertTimeline(streamingSampleEvent(id: "20000000-0000-4000-8000-000000000001"))
        try extra.writeHashManifest()
        let extraBefore = try Data(contentsOf: extra.databaseURL)
        #expect(throws: (any Error).self) { try extra.verifyIntegrity() }
        #expect(try Data(contentsOf: extra.databaseURL) == extraBefore)
    }

    @Test(.enabled(
        if: ProcessInfo.processInfo.environment["ROOTSTOCK_BLUE_RUN_100K_TEST"] == "1",
        "set ROOTSTOCK_BLUE_RUN_100K_TEST=1 for the bounded-memory verification workload"
    ))
    func oneHundredThousandEventIntegrityWhenExplicitlyRequested() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let package = try CasePackage.create(at: scratch.appendingPathComponent("large.rsbcase"))
        var events: [EventEnvelope]? = (0..<100_000).map { index in
            streamingSampleEvent(id: String(format: "30000000-0000-4000-8000-%012d", index))
        }
        try package.appendEventBatch(events!, stream: "es", custody: nil)
        events = nil
        #expect(throws: Never.self) { try package.verifyIntegrity() }
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
