import Darwin
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
    var writeLockURL: URL { rootURL.appendingPathComponent(".rsbcase-write-lock", isDirectory: true) }
    var writeJournalURL: URL { writeLockURL.appendingPathComponent("journal.json") }

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
        try pkg.writeHashManifest()
        try pkg.appendCustody(
            CustodyEvent(actor: actor, action: "create", detail: "Case package created")
        )
        return pkg
    }

    public static func open(at url: URL) throws -> CasePackage {
        let manifestURL = url.appendingPathComponent("manifest.json")
        do {
            try CaseFilesystem.requireDirectory(at: url, label: "case root")
            try CaseFilesystem.requireRegularFile(at: manifestURL, label: "manifest.json")
        } catch RootstockBlueError.invalidCasePackage {
            throw RootstockBlueError.caseNotFound(url)
        }
        let data = try Data(contentsOf: manifestURL)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let manifest = try decoder.decode(CaseManifest.self, from: data)
        try validateSupportedFormat(manifest)
        try CaseFilesystem.requireRegularFile(
            at: url.appendingPathComponent("case.sqlite"),
            label: "case.sqlite"
        )
        return CasePackage(rootURL: url, manifest: manifest)
    }

    public func appendCustody(_ event: CustodyEvent) throws {
        try beginWriteJournal(operation: "custody", target: relativePath(for: custodyURL), eventID: nil)
        do {
            try verifyIntegrity(allowWriteJournal: true)
            try CustodyLog.append(url: custodyURL, event: event)
            let db = try CaseDatabase(url: databaseURL)
            try db.transaction {
                try db.insertCustody(event)
            }
            try writeHashManifest(allowWriteJournal: true)
            try clearWriteJournal()
        } catch {
            throw error
        }
    }

    /// Records an event in its JSONL stream and SQLite projection.
    /// The write journal is fail-closed interruption detection, not a power-loss
    /// durability or atomic-recording guarantee.
    public func appendEvent(_ envelope: EventEnvelope, stream: String = "es") throws {
        try appendEventBatch([envelope], stream: stream, custody: nil)
    }

    /// Records a validated event batch and optional import custody record.
    public func appendEventBatch(
        _ events: [EventEnvelope],
        stream: String,
        custody: CustodyEvent?
    ) throws {
        try appendEventBatch(events, stream: stream, custody: custody, afterEventWrite: nil)
    }

    func appendEventBatch(
        _ events: [EventEnvelope],
        stream: String,
        custody: CustodyEvent?,
        afterEventWrite: ((Int) throws -> Void)?,
        beforeWriteLock: (() throws -> Void)? = nil,
        afterIntegrityCheck: (() throws -> Void)? = nil,
        afterHashManifestWrite: (() throws -> Void)? = nil
    ) throws {
        guard !events.isEmpty || custody != nil else { return }
        let eventIDs = events.map { $0.id.uuidString }
        guard Set(eventIDs).count == eventIDs.count else {
            throw RootstockBlueError.invalidCasePackage("duplicate event IDs in write batch")
        }
        try beforeWriteLock?()
        try beginWriteJournal(
            operation: "event_batch",
            target: "events/\(stream)",
            eventID: eventIDs.first
        )
        var mutationStarted = false
        do {
            try verifyIntegrity(allowWriteJournal: true)
            try afterIntegrityCheck?()
            // This is authoritative: a competing writer may have completed after
            // this caller formed its batch but before it acquired the journal.
            let readOnlyDatabase = try CaseDatabase(url: databaseURL, readOnly: true)
            try readOnlyDatabase.requireTimelineEventIDsAbsent(eventIDs)
            let database = try CaseDatabase(url: databaseURL)
            mutationStarted = true
            try database.transaction {
                for (index, event) in events.enumerated() {
                    try appendEventJSONL(event, to: try eventJSONLURL(for: event, stream: stream))
                    try afterEventWrite?(index)
                }
                for event in events {
                    try database.insertTimeline(event)
                }
                if let custody {
                    try CustodyLog.append(url: custodyURL, event: custody)
                    try database.insertCustody(custody)
                }
            }
            try writeHashManifest(allowWriteJournal: true)
            try afterHashManifestWrite?()
            try clearWriteJournal()
        } catch {
            if !mutationStarted {
                try? clearWriteJournal()
            }
            throw error
        }
    }

    private func appendEventJSONL(_ envelope: EventEnvelope, to file: URL) throws {
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

    public func copyArtifact(from source: URL, relativeName: String) throws -> URL {
        try copyArtifact(from: source, relativeName: relativeName, afterStagedCopy: nil)
    }

    func copyArtifact(
        from source: URL,
        relativeName: String,
        afterStagedCopy: (() throws -> Void)?
    ) throws -> URL {
        let descriptor = try CaseFilesystem.openRegularFileNoFollow(at: source, label: "artifact source")
        defer { _ = close(descriptor) }
        return try copyArtifact(
            fromFileDescriptor: descriptor,
            sourceDescription: source.path,
            relativeName: relativeName,
            afterStagedCopy: afterStagedCopy
        )
    }

    /// Copies from a descriptor already opened by a caller using non-following
    /// traversal. The source pathname is deliberately never reopened here.
    public func copyArtifact(fromFileDescriptor descriptor: Int32, relativeName: String) throws -> URL {
        try copyArtifact(
            fromFileDescriptor: descriptor,
            sourceDescription: "descriptor:\(descriptor)",
            relativeName: relativeName,
            afterStagedCopy: nil
        )
    }

    private func copyArtifact(
        fromFileDescriptor descriptor: Int32,
        sourceDescription: String,
        relativeName: String,
        afterStagedCopy: (() throws -> Void)?
    ) throws -> URL {
        let fm = FileManager.default
        let requestedDestination = try artifactDestination(relativeName: relativeName)
        // Re-check containment on the resolved path immediately before any file operation.
        let resolvedRoot = artifactsURL.standardizedFileURL.resolvingSymlinksInPath().pathComponents
        let destination = requestedDestination.standardizedFileURL.resolvingSymlinksInPath()
        guard destination.pathComponents.count > resolvedRoot.count,
              destination.pathComponents.starts(with: resolvedRoot)
        else {
            throw RootstockBlueError.invalidCasePackage("artifact path escapes case package")
        }
        guard !fm.fileExists(atPath: destination.path) else {
            throw RootstockBlueError.invalidCasePackage("artifact already exists: \(relativeName)")
        }
        try CaseFilesystem.requireRegularFile(descriptor: descriptor, label: "artifact source")
        try beginWriteJournal(operation: "artifact", target: "artifacts/\(relativeName)", eventID: nil)
        let staging = rootURL.appendingPathComponent(".rsbcase-artifact-stage-\(UUID().uuidString)")
        do {
            try verifyIntegrity(allowWriteJournal: true)
            try prepareArtifactParent(for: relativeName)
            guard !fm.fileExists(atPath: destination.path) else {
                throw RootstockBlueError.invalidCasePackage("artifact already exists: \(relativeName)")
            }
            try CaseFilesystem.requireRegularFile(descriptor: descriptor, label: "artifact source")
            try streamArtifact(fromFileDescriptor: descriptor, to: staging)
            try afterStagedCopy?()
            try fm.moveItem(at: staging, to: destination)
            let hash = try Hashing.sha256File(at: destination)
            let custody = CustodyEvent(
                actor: NSUserName(),
                action: "artifact.copy",
                detail: "source=\(sourceDescription) destination=artifacts/\(relativeName) sha256=\(hash)"
            )
            try CustodyLog.append(url: custodyURL, event: custody)
            let database = try CaseDatabase(url: databaseURL)
            try database.insertCustody(custody)
            try writeHashManifest(allowWriteJournal: true)
            try clearWriteJournal()
            return destination
        } catch {
            throw error
        }
    }

    private func streamArtifact(fromFileDescriptor sourceDescriptor: Int32, to staging: URL) throws {
        let destinationDescriptor = Darwin.open(
            staging.path,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
            S_IRUSR | S_IWUSR
        )
        guard destinationDescriptor >= 0 else {
            throw RootstockBlueError.invalidCasePackage("cannot create artifact staging file")
        }
        let source = FileHandle(fileDescriptor: sourceDescriptor, closeOnDealloc: false)
        let destination = FileHandle(fileDescriptor: destinationDescriptor, closeOnDealloc: true)
        do {
            try source.seek(toOffset: 0)
            while let chunk = try source.read(upToCount: 64 * 1024), !chunk.isEmpty {
                try destination.write(contentsOf: chunk)
            }
            try destination.synchronize()
            try destination.close()
        } catch {
            try? destination.close()
            try? FileManager.default.removeItem(at: staging)
            throw error
        }
    }

    private func artifactDestination(relativeName: String) throws -> URL {
        guard isSafeRelativePath(relativeName) else {
            throw RootstockBlueError.invalidCasePackage("invalid artifact relative path")
        }
        let root = artifactsURL.standardizedFileURL
        let destination = root.appendingPathComponent(relativeName).standardizedFileURL
        guard destination.path.hasPrefix(root.path + "/") else {
            throw RootstockBlueError.invalidCasePackage("artifact path escapes case package")
        }
        return destination
    }

    /// Creates only validated real-directory parents, after the sealed package has
    /// passed verification under the exclusive write lock.
    private func prepareArtifactParent(for relativeName: String) throws {
        var parent = artifactsURL.standardizedFileURL
        let rootValues = try parent.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        guard rootValues.isDirectory == true, rootValues.isSymbolicLink != true else {
            throw RootstockBlueError.invalidCasePackage("artifact root is not a real directory")
        }
        for component in relativeName.split(separator: "/").dropLast() {
            parent.appendPathComponent(String(component), isDirectory: true)
            if FileManager.default.fileExists(atPath: parent.path) {
                let values = try parent.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
                guard values.isDirectory == true, values.isSymbolicLink != true else {
                    throw RootstockBlueError.invalidCasePackage("artifact parent is not a real directory")
                }
            } else {
                try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false)
            }
        }
    }

    private func eventJSONLURL(for envelope: EventEnvelope, stream: String) throws -> URL {
        let dir = stream == "net" ? eventsNetURL : eventsESURL
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let day = CaseTimestamp.string(from: envelope.eventTime).prefix(10)
        return dir.appendingPathComponent("\(day).jsonl")
    }

}

struct CaseWriteJournal: Codable {
    let formatVersion: Int
    let operation: String
    let target: String
    let eventID: String?

    init(operation: String, target: String, eventID: String?) {
        formatVersion = 1
        self.operation = operation
        self.target = target
        self.eventID = eventID
    }
}
