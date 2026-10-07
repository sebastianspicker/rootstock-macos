import Foundation

/// Provenance of a normalized event in a case.
public enum EventSource: String, Codable, Sendable {
    case es
    case parser
    case uls
    case santa
    case collect
    case network
    case synthetic
}

/// JSONL-friendly event wrapper shared by offline parsers and synthetic fixtures.
public struct EventEnvelope: Codable, Sendable, Identifiable {
    public struct Identity: Sendable {
        public var id: UUID
        public var kind: String
        public var label: String

        public init(id: UUID = UUID(), kind: String, label: String) {
            self.id = id
            self.kind = kind
            self.label = label
        }
    }

    public struct Capture: Sendable {
        public var source: EventSource
        public var eventTime: Date
        public var collectedAt: Date

        public init(source: EventSource, eventTime: Date = Date(), collectedAt: Date = Date()) {
            self.source = source
            self.eventTime = eventTime
            self.collectedAt = collectedAt
        }
    }

    public struct Payload: Sendable {
        public var entityRefs: [EntityID]
        public var properties: [String: String]
        public var provenance: String?
        public var confidence: Double

        public init(
            entityRefs: [EntityID] = [],
            properties: [String: String] = [:],
            provenance: String? = nil,
            confidence: Double = 1.0
        ) {
            self.entityRefs = entityRefs
            self.properties = properties
            self.provenance = provenance
            self.confidence = confidence
        }
    }

    public var id: UUID
    public var eventTime: Date
    public var collectedAt: Date
    public var source: EventSource
    public var sourcePlugin: String
    public var eventType: String
    public var entityRefs: [EntityID]
    public var fields: [String: String]
    public var rawRef: String?
    public var confidence: Double

    public init(identity: Identity, capture: Capture, payload: Payload) {
        id = identity.id
        eventTime = capture.eventTime
        collectedAt = capture.collectedAt
        source = capture.source
        sourcePlugin = identity.label
        eventType = identity.kind
        entityRefs = payload.entityRefs
        fields = payload.properties
        rawRef = payload.provenance
        confidence = payload.confidence
    }

}

/// Decode/encode `EventEnvelope` rows as JSONL (one ISO-8601 JSON object per line).
public enum EventJSONL {
    public static func decode(text: String, skipInvalid: Bool = false) throws -> [EventEnvelope] {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        var events: [EventEnvelope] = []
        for line in text.split(whereSeparator: { $0 == "\n" || $0 == "\r\n" || $0 == "\r" }) {
            let s = String(line).trimmingCharacters(in: .whitespaces)
            guard !s.isEmpty, let data = s.data(using: .utf8) else { continue }
            if skipInvalid {
                if let e = try? decoder.decode(EventEnvelope.self, from: data) {
                    events.append(e)
                }
            } else {
                events.append(try decoder.decode(EventEnvelope.self, from: data))
            }
        }
        return events
    }

    public static func decode(contentsOf url: URL, skipInvalid: Bool = false) throws -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        try forEach(contentsOf: url, skipInvalid: skipInvalid) { events.append($0) }
        return events
    }

    /// Incrementally decodes a JSONL file in fixed-size chunks. The callback is
    /// invoked in file order, and callback errors are never treated as invalid
    /// JSON records even when `skipInvalid` is enabled.
    public static func forEach(
        contentsOf url: URL,
        skipInvalid: Bool = false,
        _ body: (EventEnvelope) throws -> Void
    ) throws {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        try JSONLRecordReader.forEachRecord(contentsOf: url) { record in
            let text = try JSONLRecordReader.strictUTF8(record)
                .trimmingCharacters(in: .whitespaces)
            guard !text.isEmpty else { return }
            let data = Data(text.utf8)
            if skipInvalid {
                guard let event = try? decoder.decode(EventEnvelope.self, from: data) else { return }
                try body(event)
            } else {
                try body(decoder.decode(EventEnvelope.self, from: data))
            }
        }
    }

    public static func encode(_ events: [EventEnvelope]) throws -> Data {
        try encode(sequence: events)
    }

    /// Compatibility data wrapper. Use `write(sequence:_:)` when the caller can
    /// consume lines incrementally.
    public static func encode<S: Sequence>(sequence events: S) throws -> Data where S.Element == EventEnvelope {
        var data = Data()
        _ = try write(sequence: events) { data.append($0) }
        return data
    }

    /// Encodes and emits one complete JSONL record at a time without retaining
    /// the input sequence or aggregate output.
    @discardableResult
    public static func write<S: Sequence>(
        sequence events: S,
        _ writeLine: (Data) throws -> Void
    ) throws -> Int where S.Element == EventEnvelope {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        var count = 0
        for event in events {
            var line = try encoder.encode(event)
            line.append(contentsOf: "\n".utf8)
            try writeLine(line)
            count += 1
        }
        return count
    }

    /// File-handle convenience for the incremental sequence writer.
    @discardableResult
    public static func write<S: Sequence>(
        sequence events: S,
        to handle: FileHandle
    ) throws -> Int where S.Element == EventEnvelope {
        try write(sequence: events) { try handle.write(contentsOf: $0) }
    }

    /// Retains the original array-shaped file writer convenience.
    @discardableResult
    public static func write(_ events: [EventEnvelope], to handle: FileHandle) throws -> Int {
        try write(sequence: events, to: handle)
    }

    public static func encodeLine(_ event: EventEnvelope) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        var data = try encoder.encode(event)
        data.append(contentsOf: "\n".utf8)
        return data
    }
}

/// Byte-oriented JSONL framing shared by strict case readers. A record ends at
/// `\n`; a trailing `\r` (CRLF) is tolerated and stripped.
public enum JSONLRecordReader {
    public static let chunkSize = 64 * 1024

    public static func forEachRecord(
        contentsOf url: URL,
        _ body: (Data) throws -> Void
    ) throws {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var buffer = Data()
        var scanOffset = 0
        while let chunk = try handle.read(upToCount: chunkSize), !chunk.isEmpty {
            buffer.append(chunk)
            try emitCompleteRecords(from: &buffer, scanOffset: &scanOffset, body)
        }
        if !buffer.isEmpty {
            _ = try strictUTF8(buffer)
            try body(buffer)
        }
    }

    public static func strictUTF8(_ data: Data) throws -> String {
        guard let value = String(data: data, encoding: .utf8) else {
            throw CocoaError(.fileReadInapplicableStringEncoding)
        }
        return value
    }

    private static func emitCompleteRecords(
        from buffer: inout Data,
        scanOffset: inout Int,
        _ body: (Data) throws -> Void
    ) throws {
        var recordStart = 0
        var index = scanOffset
        while index < buffer.count {
            guard let width = newlineWidth(in: buffer, at: index) else {
                index += 1
                continue
            }
            var record = buffer.subdata(in: recordStart..<index)
            if record.last == 0x0D { record.removeLast() }
            _ = try strictUTF8(record)
            try body(record)
            index += width
            recordStart = index
        }
        if recordStart > 0 {
            buffer.removeSubrange(0..<recordStart)
            index -= recordStart
        }
        scanOffset = index
    }

    /// JSONL records are separated by `\n` only; U+0085, U+2028 and U+2029 are valid unescaped
    /// characters inside JSON strings and must not split a record.
    private static func newlineWidth(in data: Data, at index: Int) -> Int? {
        data[index] == 0x0A ? 1 : nil
    }
}

/// Detection finding produced by rules against events.
public struct Finding: Codable, Sendable, Identifiable {
    public var id: UUID
    public var ruleID: String
    public var title: String
    public var severity: String
    public var eventIDs: [UUID]
    public var attackTechniques: [String]
    public var evidenceSummary: String
    public var createdAt: Date

    public init(
        id: UUID = UUID(),
        ruleID: String,
        title: String,
        severity: String,
        eventIDs: [UUID],
        attackTechniques: [String] = [],
        evidenceSummary: String,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.ruleID = ruleID
        self.title = title
        self.severity = severity
        self.eventIDs = eventIDs
        self.attackTechniques = attackTechniques
        self.evidenceSummary = evidenceSummary
        self.createdAt = createdAt
    }
}
