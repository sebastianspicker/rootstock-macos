/// CustodyLog - Rootstock product source (see package README for product doctrine).
import Foundation
import RootstockBlueCore

public struct CustodyEvent: Codable, Sendable {
    public var timestamp: Date
    public var actor: String
    public var action: String
    public var detail: String

    public init(timestamp: Date = Date(), actor: String, action: String, detail: String = "") {
        self.timestamp = timestamp
        self.actor = actor
        self.action = action
        self.detail = detail
    }
}

public enum CustodyLog {
    public static func append(url: URL, event: CustodyEvent) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(event)
        var line = data
        line.append(contentsOf: "\n".utf8)
        if FileManager.default.fileExists(atPath: url.path) {
            let handle = try FileHandle(forWritingTo: url)
            defer { try? handle.close() }
            try handle.seekToEnd()
            try handle.write(contentsOf: line)
        } else {
            try line.write(to: url)
        }
    }

    /// Strictly decode every custody JSONL record. Any malformed record invalidates the package.
    public static func decode(contentsOf url: URL) throws -> [CustodyEvent] {
        var events: [CustodyEvent] = []
        try forEach(contentsOf: url) { events.append($0) }
        return events
    }

    /// Strictly stream custody records in file order without retaining the log.
    public static func forEach(
        contentsOf url: URL,
        _ body: (CustodyEvent) throws -> Void
    ) throws {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        try JSONLRecordReader.forEachRecord(contentsOf: url) { record in
            let text = try JSONLRecordReader.strictUTF8(record)
                .trimmingCharacters(in: .whitespaces)
            guard !text.isEmpty else { return }
            try body(decoder.decode(CustodyEvent.self, from: Data(text.utf8)))
        }
    }
}
