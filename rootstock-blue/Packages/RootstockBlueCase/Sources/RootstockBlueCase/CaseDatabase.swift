import Foundation
import SQLite3
import RootstockBlueCore

/// Case SQLite handle with exclusive ownership.
///
/// Not `Sendable`: the C `OpaquePointer` is confined to this instance and must not
/// cross isolation domains. Call sites open, use, and release on one task/thread.
/// SQLite is opened with `SQLITE_OPEN_FULLMUTEX` for internal C-level serialization.
public final class CaseDatabase {
    private var db: OpaquePointer?

    public init(url: URL) throws {
        let flags = SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX
        db = try SQLiteSupport.open(path: url.path, flags: flags)
        try migrate()
    }

    deinit {
        SQLiteSupport.close(db)
        db = nil
    }

    public func migrate() throws {
        for sql in CaseSchema.createStatements {
            try SQLiteSupport.exec(db, sql: sql)
        }
        try SQLiteSupport.execute(
            db,
            sql: "INSERT OR REPLACE INTO schema_meta(key, value) VALUES(?, ?);",
            bindings: [.text("version"), .text(String(CaseSchema.version))]
        )
    }

    /// Execute static SQL (no dynamic values). Prefer `execute(_:bindings:)` for parameters.
    public func exec(_ sql: String) throws {
        try SQLiteSupport.exec(db, sql: sql)
    }

    /// Execute a prepared statement with bound parameters.
    public func execute(_ sql: String, bindings: [SQLiteBindValue] = []) throws {
        try SQLiteSupport.execute(db, sql: sql, bindings: bindings)
    }

    public func queryScalar(_ sql: String, bindings: [SQLiteBindValue] = []) throws -> String? {
        try SQLiteSupport.queryScalar(db, sql: sql, bindings: bindings)
    }

    public func queryRows(_ sql: String, bindings: [SQLiteBindValue] = []) throws -> [[String: String]] {
        try SQLiteSupport.queryRows(db, sql: sql, bindings: bindings)
    }

    public func insertTimeline(_ event: EventEnvelope) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let fieldsData = (try? encoder.encode(event.fields)).flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
        let refs = event.entityRefs.map(\.description).joined(separator: ",")
        let summary = event.fields[FieldTaxonomy.processPath]
            ?? event.fields[FieldTaxonomy.filePath]
            ?? event.fields[FieldTaxonomy.tccIdentity]
            ?? event.eventType
        let iso = ISO8601DateFormatter()
        try SQLiteSupport.execute(
            db,
            sql: """
            INSERT OR REPLACE INTO timeline_events(
              id, event_time, collected_at, source, source_plugin, event_type, summary, entity_refs, fields_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            bindings: [
                .text(event.id.uuidString),
                .text(iso.string(from: event.eventTime)),
                .text(iso.string(from: event.collectedAt)),
                .text(event.source.rawValue),
                .text(event.sourcePlugin),
                .text(event.eventType),
                .text(summary),
                .text(refs),
                .text(fieldsData),
            ]
        )
    }

    public func insertCustody(_ event: CustodyEvent) throws {
        let ts = ISO8601DateFormatter().string(from: event.timestamp)
        try SQLiteSupport.execute(
            db,
            sql: "INSERT INTO custody_events(timestamp, actor, action, detail) VALUES(?, ?, ?, ?);",
            bindings: [
                .text(ts),
                .text(event.actor),
                .text(event.action),
                .text(event.detail),
            ]
        )
    }
}
