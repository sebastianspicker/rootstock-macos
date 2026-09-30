import Foundation
import SQLite3
import RootstockBlueCore

/// Case SQLite handle with exclusive ownership.
///
/// Not `Sendable`: the C `OpaquePointer` is confined to this instance and must not
/// cross isolation domains. Call sites open, use, and release on one task/thread.
/// SQLite is opened with `SQLITE_OPEN_FULLMUTEX` for internal C-level serialization.
public final class CaseDatabase {
    fileprivate var db: OpaquePointer?

    public init(url: URL, readOnly: Bool = false) throws {
        let flags = (readOnly ? SQLITE_OPEN_READONLY : SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE)
            | SQLITE_OPEN_FULLMUTEX
        db = try SQLiteSupport.open(path: url.path, flags: flags)
        if !readOnly {
            try migrate()
        }
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
            sql: "INSERT OR IGNORE INTO schema_meta(key, value) VALUES(?, ?);",
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

    /// Groups SQLite projection changes for one logical case write. This is a
    /// database transaction only; case-directory crash/power-loss durability is
    /// intentionally outside the v0 package contract.
    public func transaction<T>(_ body: () throws -> T) throws -> T {
        try SQLiteSupport.exec(db, sql: "BEGIN IMMEDIATE TRANSACTION;")
        do {
            let result = try body()
            try SQLiteSupport.exec(db, sql: "COMMIT;")
            return result
        } catch {
            try? SQLiteSupport.exec(db, sql: "ROLLBACK;")
            throw error
        }
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
        try SQLiteSupport.execute(
            db,
            sql: """
            INSERT INTO timeline_events(
              id, event_time, collected_at, source, source_plugin, event_type, summary, entity_refs, fields_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            bindings: [
                .text(event.id.uuidString),
                .text(CaseTimestamp.string(from: event.eventTime)),
                .text(CaseTimestamp.string(from: event.collectedAt)),
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
        let ts = CaseTimestamp.string(from: event.timestamp)
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

    public func timelineEventIDs() throws -> [String] {
        try queryRows("SELECT id FROM timeline_events ORDER BY id;").compactMap { $0["id"] }
    }

    /// Checks candidate membership with one reusable prepared statement rather
    /// than materializing all historical IDs.
    func requireTimelineEventIDsAbsent(_ eventIDs: [String]) throws {
        let statement = try SQLitePreparedStatement(
            database: self,
            sql: "SELECT 1 FROM timeline_events WHERE id = ? LIMIT 1;"
        )
        for eventID in eventIDs {
            try statement.bindText(eventID)
            if try statement.step() == SQLITE_ROW {
                throw RootstockBlueError.invalidCasePackage("event ID already exists in case")
            }
        }
    }

    /// Creates a bounded-memory verifier on this connection. SQLite TEMP storage
    /// is explicitly file-backed; inability to establish it fails verification.
    func makeEventProjectionVerifier() throws -> CaseEventProjectionVerifier {
        try exec("PRAGMA temp_store = FILE;")
        guard try queryScalar("PRAGMA temp_store;") == "1" else {
            throw RootstockBlueError.invalidCasePackage("file-backed SQLite TEMP storage unavailable")
        }
        try exec("PRAGMA main.cache_size = -2048;")
        try exec("PRAGMA temp.cache_size = -64;")
        try exec("PRAGMA temp.cache_spill = ON;")
        do {
            // Exceed the TEMP cache once so setup proves that file-backed spill
            // storage is usable rather than only accepting the PRAGMA setting.
            try exec("CREATE TEMP TABLE integrity_temp_probe(payload BLOB);")
            try exec("INSERT INTO integrity_temp_probe(payload) VALUES(zeroblob(262144));")
            try exec("DROP TABLE integrity_temp_probe;")
            try exec("PRAGMA temp.cache_size = -512;")
            try exec("CREATE TEMP TABLE integrity_seen_event_ids(id TEXT PRIMARY KEY) WITHOUT ROWID;")
            try exec("BEGIN TRANSACTION;")
        } catch {
            throw RootstockBlueError.invalidCasePackage("SQLite TEMP seen-ID table unavailable")
        }
        return try CaseEventProjectionVerifier(database: self)
    }

    func makeCustodyProjectionCursor() throws -> CaseCustodyProjectionCursor {
        try exec("PRAGMA main.cache_size = -2048;")
        return try CaseCustodyProjectionCursor(database: self)
    }
}

final class CaseEventProjectionVerifier {
    private let database: CaseDatabase
    private let lookup: SQLitePreparedStatement
    private let markSeen: SQLitePreparedStatement
    private(set) var eventCount = 0
    private var transactionActive = true

    fileprivate init(database: CaseDatabase) throws {
        self.database = database
        lookup = try SQLitePreparedStatement(
            database: database,
            sql: """
            SELECT id, event_time, collected_at, source, source_plugin, event_type,
                   summary, entity_refs, fields_json
            FROM timeline_events WHERE id = ? LIMIT 1;
            """
        )
        markSeen = try SQLitePreparedStatement(
            database: database,
            sql: "INSERT INTO temp.integrity_seen_event_ids(id) VALUES(?);"
        )
    }

    deinit {
        if transactionActive { try? database.exec("ROLLBACK;") }
    }

    func projectionRow(for eventID: String) throws -> [String: String]? {
        try markSeen.bindText(eventID)
        guard try markSeen.step() == SQLITE_DONE else {
            throw RootstockBlueError.invalidCasePackage("duplicate JSONL event IDs")
        }
        eventCount += 1

        try lookup.bindText(eventID)
        guard try lookup.step() == SQLITE_ROW else { return nil }
        return lookup.currentRow()
    }

    func finish() throws {
        do {
            let sqliteCount = Int(try database.queryScalar("SELECT COUNT(*) FROM timeline_events;") ?? "-1") ?? -1
            guard sqliteCount == eventCount else {
                throw RootstockBlueError.invalidCasePackage(
                    "JSONL/SQLite timeline projection mismatch jsonl=\(eventCount) sqlite=\(sqliteCount)"
                )
            }
            let extra = try database.queryScalar(
                """
                SELECT timeline_events.id
                FROM timeline_events
                LEFT JOIN temp.integrity_seen_event_ids AS seen ON seen.id = timeline_events.id
                WHERE seen.id IS NULL LIMIT 1;
                """
            )
            guard extra == nil else {
                throw RootstockBlueError.invalidCasePackage("extra SQLite event projection")
            }
            try database.exec("COMMIT;")
            transactionActive = false
        } catch {
            try? database.exec("ROLLBACK;")
            transactionActive = false
            throw error
        }
    }
}

final class CaseCustodyProjectionCursor {
    private let statement: SQLitePreparedStatement

    fileprivate init(database: CaseDatabase) throws {
        statement = try SQLitePreparedStatement(
            database: database,
            sql: "SELECT timestamp, actor, action, detail FROM custody_events ORDER BY id;"
        )
    }

    func next() throws -> [String: String]? {
        let result = try statement.step(resetBeforeStep: false)
        if result == SQLITE_ROW { return statement.currentRow() }
        return nil
    }
}

private final class SQLitePreparedStatement {
    private let database: CaseDatabase
    private var statement: OpaquePointer?

    init(database: CaseDatabase, sql: String) throws {
        self.database = database
        guard sqlite3_prepare_v2(database.db, sql, -1, &statement, nil) == SQLITE_OK,
              statement != nil
        else {
            throw RootstockBlueError.io("prepare failed: \(SQLiteSupport.errmsg(database.db))")
        }
    }

    deinit {
        sqlite3_finalize(statement)
        statement = nil
    }

    func bindText(_ value: String) throws {
        guard let statement else { throw RootstockBlueError.io("SQLite statement is closed") }
        sqlite3_reset(statement)
        sqlite3_clear_bindings(statement)
        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        guard sqlite3_bind_text(statement, 1, value, -1, transient) == SQLITE_OK else {
            throw RootstockBlueError.io("bind failed: \(SQLiteSupport.errmsg(database.db))")
        }
    }

    func step(resetBeforeStep: Bool = false) throws -> Int32 {
        guard let statement else { throw RootstockBlueError.io("SQLite statement is closed") }
        if resetBeforeStep { sqlite3_reset(statement) }
        let result = sqlite3_step(statement)
        guard result == SQLITE_ROW || result == SQLITE_DONE else {
            if result == SQLITE_CONSTRAINT {
                throw RootstockBlueError.invalidCasePackage("duplicate JSONL event IDs")
            }
            throw RootstockBlueError.io("sqlite step failed: \(SQLiteSupport.errmsg(database.db))")
        }
        return result
    }

    func currentRow() -> [String: String] {
        guard let statement else { return [:] }
        var row: [String: String] = [:]
        for index in 0..<sqlite3_column_count(statement) {
            let name = String(cString: sqlite3_column_name(statement, index))
            if let value = sqlite3_column_text(statement, index) {
                row[name] = String(cString: value)
            } else {
                row[name] = ""
            }
        }
        return row
    }
}
