import Foundation
import RootstockBlueCore

/// Open case directory package (`.rsbcase`).
public struct CasePackage: Sendable {
    public let rootURL: URL
    public let manifest: CaseManifest

    public var manifestURL: URL { rootURL.appendingPathComponent("manifest.json") }
    public var custodyURL: URL { rootURL.appendingPathComponent("custody.jsonl") }
    public var databaseURL: URL { rootURL.appendingPathComponent("case.sqlite") }
    public var eventsESURL: URL { rootURL.appendingPathComponent("events/es", isDirectory: true) }
    public var eventsNetURL: URL { rootURL.appendingPathComponent("events/net", isDirectory: true) }
    public var artifactsURL: URL { rootURL.appendingPathComponent("artifacts", isDirectory: true) }
    public var logarchivesURL: URL { rootURL.appendingPathComponent("logarchives", isDirectory: true) }
    public var pluginsURL: URL { rootURL.appendingPathComponent("plugins", isDirectory: true) }
    public var sha256sumsURL: URL { rootURL.appendingPathComponent("sha256sums.txt") }

    public static func create(
        at url: URL,
        name: String? = nil,
        mode: ProductMode? = nil,
        actor: String = NSUserName()
    ) throws -> CasePackage {
        let fm = FileManager.default
        if fm.fileExists(atPath: url.path) {
            throw RootstockBlueError.caseAlreadyExists(url)
        }

        let dirs = [
            url,
            url.appendingPathComponent("events/es", isDirectory: true),
            url.appendingPathComponent("events/net", isDirectory: true),
            url.appendingPathComponent("artifacts", isDirectory: true),
            url.appendingPathComponent("logarchives", isDirectory: true),
            url.appendingPathComponent("plugins", isDirectory: true),
        ]
        for dir in dirs {
            try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        }

        let caseName = name ?? url.deletingPathExtension().lastPathComponent
        let manifest = CaseManifest(name: caseName, mode: mode)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let manifestData = try encoder.encode(manifest)
        try manifestData.write(to: url.appendingPathComponent("manifest.json"))

        let dbURL = url.appendingPathComponent("case.sqlite")
        _ = try CaseDatabase(url: dbURL)

        try "".write(to: url.appendingPathComponent("custody.jsonl"), atomically: true, encoding: .utf8)
        try "".write(to: url.appendingPathComponent("sha256sums.txt"), atomically: true, encoding: .utf8)

        let pkg = CasePackage(rootURL: url, manifest: manifest)
        try pkg.appendCustody(
            CustodyEvent(actor: actor, action: "create", detail: "Case package created")
        )
        try pkg.updateHashes()
        return pkg
    }

    public static func open(at url: URL) throws -> CasePackage {
        let manifestURL = url.appendingPathComponent("manifest.json")
        guard FileManager.default.fileExists(atPath: manifestURL.path) else {
            throw RootstockBlueError.caseNotFound(url)
        }
        let data = try Data(contentsOf: manifestURL)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let manifest = try decoder.decode(CaseManifest.self, from: data)
        guard FileManager.default.fileExists(atPath: url.appendingPathComponent("case.sqlite").path) else {
            throw RootstockBlueError.invalidCasePackage("missing case.sqlite")
        }
        return CasePackage(rootURL: url, manifest: manifest)
    }

    public func appendCustody(_ event: CustodyEvent) throws {
        try CustodyLog.append(url: custodyURL, event: event)
        let db = try CaseDatabase(url: databaseURL)
        try db.insertCustody(event)
    }

    public func appendEventJSONL(_ envelope: EventEnvelope, stream: String = "es") throws {
        let dir = stream == "net" ? eventsNetURL : eventsESURL
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let day = ISO8601DateFormatter().string(from: envelope.eventTime).prefix(10)
        let file = dir.appendingPathComponent("\(day).jsonl")
        let data = try EventJSONL.encodeLine(envelope)
        if FileManager.default.fileExists(atPath: file.path) {
            let handle = try FileHandle(forWritingTo: file)
            defer { try? handle.close() }
            try handle.seekToEnd()
            try handle.write(contentsOf: data)
        } else {
            try data.write(to: file)
        }
    }

    public func openDatabase() throws -> CaseDatabase {
        try CaseDatabase(url: databaseURL)
    }

    public func verifyLayout() throws {
        let required = ["manifest.json", "case.sqlite", "custody.jsonl", "sha256sums.txt"]
        for name in required {
            let path = rootURL.appendingPathComponent(name).path
            guard FileManager.default.fileExists(atPath: path) else {
                throw RootstockBlueError.invalidCasePackage("missing \(name)")
            }
        }
    }

    public func updateHashes() throws {
        var lines: [String] = []
        let files = ["manifest.json", "case.sqlite", "custody.jsonl"]
        for name in files {
            let url = rootURL.appendingPathComponent(name)
            if FileManager.default.fileExists(atPath: url.path) {
                let hash = try Hashing.sha256File(at: url)
                lines.append("\(hash)  \(name)")
            }
        }
        try lines.joined(separator: "\n").write(to: sha256sumsURL, atomically: true, encoding: .utf8)
    }

    public func insertTimelineEvent(_ event: EventEnvelope) throws {
        let db = try openDatabase()
        try db.insertTimeline(event)
    }

    /// Load all JSONL events from es/ and net/ streams.
    public func loadAllEvents() throws -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        for dir in [eventsESURL, eventsNetURL] {
            guard let files = try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil) else {
                continue
            }
            for file in files where file.pathExtension == "jsonl" {
                events.append(contentsOf: try EventJSONL.decode(contentsOf: file, skipInvalid: true))
            }
        }
        return events
    }

    public func eventJSONLFileCount() -> Int {
        var count = 0
        for dir in [eventsESURL, eventsNetURL] {
            if let files = try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil) {
                count += files.filter { $0.pathExtension == "jsonl" }.count
            }
        }
        return count
    }

    public func copyArtifact(from source: URL, relativeName: String) throws -> URL {
        let dest = artifactsURL.appendingPathComponent(relativeName)
        try FileManager.default.createDirectory(at: dest.deletingLastPathComponent(), withIntermediateDirectories: true)
        if FileManager.default.fileExists(atPath: dest.path) {
            try FileManager.default.removeItem(at: dest)
        }
        try FileManager.default.copyItem(at: source, to: dest)
        return dest
    }
}
