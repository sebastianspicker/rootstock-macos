import Foundation
import RootstockBlueCore

extension CasePackage {
    public func verifyLayout() throws {
        try CaseFilesystem.requireDirectory(at: rootURL, label: "case root")
        let requiredFiles = ["manifest.json", "case.sqlite", "custody.jsonl", "sha256sums.txt"]
        for name in requiredFiles {
            try CaseFilesystem.requireRegularFile(at: rootURL.appendingPathComponent(name), label: name)
        }
        let requiredDirectories = ["events/es", "events/net", "artifacts", "logarchives", "plugins"]
        for name in requiredDirectories {
            var directory = rootURL
            for component in name.split(separator: "/") {
                directory.appendPathComponent(String(component), isDirectory: true)
                try CaseFilesystem.requireDirectory(at: directory, label: "directory \(directory.path)")
            }
        }
    }

    func writeHashManifest(allowWriteJournal: Bool = false) throws {
        if !allowWriteJournal, FileManager.default.fileExists(atPath: writeLockURL.path) {
            throw RootstockBlueError.invalidCasePackage("unfinished case write journal")
        }
        var lines: [String] = []
        for url in try canonicalEvidenceFiles() {
            lines.append("\(try Hashing.sha256File(at: url))  \(relativePath(for: url))")
        }
        try (lines.sorted().joined(separator: "\n") + "\n").write(
            to: sha256sumsURL, atomically: true, encoding: .utf8
        )
    }

    /// Load all JSONL events from es/ and net/ streams.
    public func loadAllEvents() throws -> [EventEnvelope] {
        try verifyIntegrity()
        var events: [EventEnvelope] = []
        try forEachEvent { events.append($0) }
        return events
    }

    private func forEachEvent(_ body: (EventEnvelope) throws -> Void) throws {
        for dir in [eventsESURL, eventsNetURL] {
            let files = try FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)
            for file in files.sorted(by: { $0.path < $1.path }) where file.pathExtension == "jsonl" {
                try CaseFilesystem.requireRegularFile(at: file, label: "event file \(file.lastPathComponent)")
                try EventJSONL.forEach(contentsOf: file, body)
            }
        }
    }

    /// Verifies the complete evidence inventory, strict checksum manifest, JSONL, and SQLite projection.
    public func verifyIntegrity() throws {
        try verifyIntegrity(allowWriteJournal: false)
    }

    func verifyIntegrity(allowWriteJournal: Bool) throws {
        try Self.validateSupportedFormat(manifest)
        try Self.validateSupportedFormat(try Self.loadManifest(at: manifestURL))
        try verifyLayout()
        try verifyWriteJournal(allowWriteJournal)
        try verifyEvidenceChecksums()
        try verifyEventProjection()
        try verifyCustodyProjection()
    }

    private func verifyWriteJournal(_ allowWriteJournal: Bool) throws {
        guard allowWriteJournal || !FileManager.default.fileExists(atPath: writeLockURL.path) else {
            throw RootstockBlueError.invalidCasePackage("unfinished case write journal")
        }
    }

    private func verifyEvidenceChecksums() throws {
        let expected = try parseChecksumManifest()
        let inventory = try canonicalEvidenceFiles()
        let relativeInventory = Set(inventory.map(relativePath(for:)))
        guard Set(expected.keys) == relativeInventory else {
            let missing = relativeInventory.subtracting(expected.keys).sorted()
            let unexpected = Set(expected.keys).subtracting(relativeInventory).sorted()
            throw RootstockBlueError.invalidCasePackage(
                "checksum inventory mismatch missing=\(missing) unexpected=\(unexpected)"
            )
        }
        for url in inventory {
            let relative = relativePath(for: url)
            guard expected[relative] == (try Hashing.sha256File(at: url)) else {
                throw RootstockBlueError.invalidCasePackage("checksum mismatch for \(relative)")
            }
        }
    }

    private func verifyEventProjection() throws {
        let database = try CaseDatabase(url: databaseURL, readOnly: true)
        let verifier = try database.makeEventProjectionVerifier()
        let fieldsDecoder = JSONDecoder()
        try forEachEvent { event in
            try verify(
                eventProjection: event,
                row: try verifier.projectionRow(for: event.id.uuidString),
                fieldsDecoder: fieldsDecoder
            )
        }
        try verifier.finish()
    }

    private func verify(
        eventProjection event: EventEnvelope,
        row: [String: String]?,
        fieldsDecoder: JSONDecoder
    ) throws {
        guard let row else {
            throw RootstockBlueError.invalidCasePackage("missing SQLite event projection")
        }
        let summary = event.fields[FieldTaxonomy.processPath]
            ?? event.fields[FieldTaxonomy.filePath]
            ?? event.fields[FieldTaxonomy.tccIdentity]
            ?? event.eventType
        let expected = [
            "event_time": CaseTimestamp.string(from: event.eventTime),
            "collected_at": CaseTimestamp.string(from: event.collectedAt),
            "source": event.source.rawValue,
            "source_plugin": event.sourcePlugin,
            "event_type": event.eventType,
            "summary": summary,
            "entity_refs": event.entityRefs.map(\.description).joined(separator: ","),
        ]
        guard expected.allSatisfy({ row[$0.key] == $0.value }),
              let fieldsData = row["fields_json"]?.data(using: .utf8),
              try fieldsDecoder.decode([String: String].self, from: fieldsData) == event.fields
        else {
            throw RootstockBlueError.invalidCasePackage("SQLite event projection differs from JSONL")
        }
    }

    private func verifyCustodyProjection() throws {
        let database = try CaseDatabase(url: databaseURL, readOnly: true)
        let cursor = try database.makeCustodyProjectionCursor()
        try CustodyLog.forEach(contentsOf: custodyURL) { event in
            guard let row = try cursor.next() else {
                throw RootstockBlueError.invalidCasePackage("custody JSONL/SQLite row count mismatch")
            }
            guard row["timestamp"] == CaseTimestamp.string(from: event.timestamp),
                  row["actor"] == event.actor,
                  row["action"] == event.action,
                  row["detail"] == event.detail
            else {
                throw RootstockBlueError.invalidCasePackage("custody JSONL/SQLite row mismatch")
            }
        }
        guard try cursor.next() == nil else {
            throw RootstockBlueError.invalidCasePackage("custody JSONL/SQLite row count mismatch")
        }
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

    func canonicalEvidenceFiles() throws -> [URL] {
        try CasePackageVerification.canonicalEvidenceFiles(
            rootURL: rootURL,
            sha256sumsURL: sha256sumsURL,
            writeLockURL: writeLockURL,
            writeJournalURL: writeJournalURL
        )
    }

    private func parseChecksumManifest() throws -> [String: String] {
        try CasePackageVerification.parseChecksumManifest(sha256sumsURL: sha256sumsURL)
    }

    func relativePath(for url: URL) -> String {
        CasePackageVerification.relativePath(for: url, rootURL: rootURL)
    }

    static func loadManifest(at url: URL) throws -> CaseManifest {
        try CasePackageVerification.loadManifest(at: url)
    }

    static func validateSupportedFormat(_ manifest: CaseManifest) throws {
        try CasePackageVerification.validateSupportedFormat(manifest)
    }

    func isSafeRelativePath(_ path: String) -> Bool {
        CasePackageVerification.isSafeRelativePath(path)
    }

    func beginWriteJournal(operation: String, target: String, eventID: String?) throws {
        let fm = FileManager.default
        do {
            try fm.createDirectory(at: writeLockURL, withIntermediateDirectories: false)
        } catch {
            throw RootstockBlueError.invalidCasePackage("case package is busy or has an unfinished write journal")
        }
        let journal = CaseWriteJournal(operation: operation, target: target, eventID: eventID)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        do {
            try encoder.encode(journal).write(to: writeJournalURL, options: .atomic)
        } catch {
            try? fm.removeItem(at: writeLockURL)
            throw error
        }
    }

    func clearWriteJournal() throws {
        try FileManager.default.removeItem(at: writeLockURL)
    }
}
