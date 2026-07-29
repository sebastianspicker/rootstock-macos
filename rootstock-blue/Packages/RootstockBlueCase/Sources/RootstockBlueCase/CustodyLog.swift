/// CustodyLog - Rootstock product source (see package README for product doctrine).
import Foundation

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
}
