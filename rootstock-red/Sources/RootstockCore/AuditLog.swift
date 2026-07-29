import Foundation

/// Single audit log record (JSONL).
public struct AuditRecord: Codable, Sendable, Equatable {
    public struct Run: Sendable {
        public var timestamp: Date = Date()
        public var mode: RunMode
        public var profile: ScanProfile
        public var allowNetwork: Bool
        public var schemaVersion: String = RootstockCore.schemaVersion

        public init(mode: RunMode, profile: ScanProfile, allowNetwork: Bool, timestamp: Date = Date(), schemaVersion: String = RootstockCore.schemaVersion) {
            self.timestamp = timestamp
            self.mode = mode
            self.profile = profile
            self.allowNetwork = allowNetwork
            self.schemaVersion = schemaVersion
        }
    }

    public struct Subject: Sendable {
        public var operatorName: String?
        public var scope: String?
        public var hostUUID: String
        public var argvSummary: String

        public init(operatorName: String?, scope: String?, hostUUID: String, argvSummary: String) {
            self.operatorName = operatorName
            self.scope = scope
            self.hostUUID = hostUUID
            self.argvSummary = argvSummary
        }
    }

    public struct Outcome: Sendable {
        public var findingCount: Int
        public var collectorIds: [String]
        public var checkIds: [String]

        public init(findingCount: Int, collectorIds: [String], checkIds: [String]) {
            self.findingCount = findingCount
            self.collectorIds = collectorIds
            self.checkIds = checkIds
        }
    }

    public var timestamp: Date
    public var mode: RunMode
    public var profile: ScanProfile
    public var operatorName: String?
    public var scope: String?
    public var hostUUID: String
    public var argvSummary: String
    public var findingCount: Int
    public var collectorIds: [String]
    public var checkIds: [String]
    public var allowNetwork: Bool
    public var schemaVersion: String

    public init(run: Run, subject: Subject, outcome: Outcome) {
        self.timestamp = run.timestamp
        self.mode = run.mode
        self.profile = run.profile
        self.operatorName = subject.operatorName
        self.scope = subject.scope
        self.hostUUID = subject.hostUUID
        self.argvSummary = subject.argvSummary
        self.findingCount = outcome.findingCount
        self.collectorIds = outcome.collectorIds
        self.checkIds = outcome.checkIds
        self.allowNetwork = run.allowNetwork
        self.schemaVersion = run.schemaVersion
    }
}

/// Append-only JSONL audit writer with actor isolation for concurrent safety.
public actor AuditLog {
    public nonisolated let fileURL: URL
    private let encoder: JSONEncoder

    public init(fileURL: URL) {
        self.fileURL = fileURL
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        self.encoder = encoder
    }

    public nonisolated static func defaultURL(projectDirectory: URL? = nil) throws -> URL {
        if let projectDirectory {
            try FileManager.default.createDirectory(
                at: projectDirectory,
                withIntermediateDirectories: true
            )
            return projectDirectory.appendingPathComponent("audit.jsonl")
        }
        try SafetyRails.ensureConfigDirectory()
        let auditDir = SafetyRails.rootstockConfigDirectory.appendingPathComponent("audit", isDirectory: true)
        try FileManager.default.createDirectory(at: auditDir, withIntermediateDirectories: true)
        let day = ISO8601DateFormatter().string(from: Date()).prefix(10)
        return auditDir.appendingPathComponent("audit-\(day).jsonl")
    }

    public func append(_ record: AuditRecord) throws {
        let data = try encoder.encode(record)
        guard var line = String(data: data, encoding: .utf8) else {
            throw RootstockError.io("failed to encode audit record")
        }
        line.append("\n")
        guard let lineData = line.data(using: .utf8) else {
            throw RootstockError.io("failed to encode audit line")
        }

        if FileManager.default.fileExists(atPath: fileURL.path) {
            let handle = try FileHandle(forWritingTo: fileURL)
            defer { try? handle.close() }
            try handle.seekToEnd()
            try handle.write(contentsOf: lineData)
        } else {
            try lineData.write(to: fileURL, options: .atomic)
        }
    }
}
