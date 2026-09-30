import Foundation
import SQLite3

/// Bound parameter values for prepared SQLite statements.
/// Prefer these over string interpolation of dynamic values into SQL text.
public enum SQLiteBindValue: Sendable, Equatable {
    case null
    case int(Int64)
    case double(Double)
    case text(String)
    case blob(Data)
}

/// Shared low-level SQLite helpers used by Case and FX offline readers.
/// Dynamic values must be bound; SQL text carries only placeholders and static DDL/DML structure.
public enum SQLiteSupport {
    public static func open(path: String, flags: Int32) throws -> OpaquePointer {
        var db: OpaquePointer?
        let rc = sqlite3_open_v2(path, &db, flags, nil)
        guard rc == SQLITE_OK, let handle = db else {
            if let db { sqlite3_close(db) }
            throw RootstockBlueError.io("sqlite open failed: \(rc)")
        }
        return handle
    }

    public static func close(_ db: OpaquePointer?) {
        if let db {
            sqlite3_close(db)
        }
    }

    public static func errmsg(_ db: OpaquePointer?) -> String {
        guard let db else { return "no database handle" }
        if let c = sqlite3_errmsg(db) {
            return String(cString: c)
        }
        return "unknown sqlite error"
    }

    /// Execute SQL that contains no dynamic values (DDL / static DML only).
    public static func exec(_ db: OpaquePointer?, sql: String) throws {
        var err: UnsafeMutablePointer<CChar>?
        let rc = sqlite3_exec(db, sql, nil, nil, &err)
        if rc != SQLITE_OK {
            let message = err.map { String(cString: $0) } ?? errmsg(db)
            sqlite3_free(err)
            throw RootstockBlueError.schemaMigrationFailed(message)
        }
    }

    /// Prepare, bind, and run a statement that does not return rows.
    public static func execute(
        _ db: OpaquePointer?,
        sql: String,
        bindings: [SQLiteBindValue] = []
    ) throws {
        let stmt = try prepare(db, sql: sql)
        defer { sqlite3_finalize(stmt) }
        try bind(stmt, bindings)
        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE || rc == SQLITE_ROW else {
            throw RootstockBlueError.io("sqlite step failed: \(errmsg(db))")
        }
    }

    public static func queryScalar(
        _ db: OpaquePointer?,
        sql: String,
        bindings: [SQLiteBindValue] = []
    ) throws -> String? {
        let stmt = try prepare(db, sql: sql)
        defer { sqlite3_finalize(stmt) }
        try bind(stmt, bindings)
        if sqlite3_step(stmt) == SQLITE_ROW {
            return columnText(stmt, 0)
        }
        return nil
    }

    public static func queryRows(
        _ db: OpaquePointer?,
        sql: String,
        bindings: [SQLiteBindValue] = []
    ) throws -> [[String: String]] {
        let stmt = try prepare(db, sql: sql)
        defer { sqlite3_finalize(stmt) }
        try bind(stmt, bindings)
        var rows: [[String: String]] = []
        let cols = sqlite3_column_count(stmt)
        while sqlite3_step(stmt) == SQLITE_ROW {
            var row: [String: String] = [:]
            for i in 0..<cols {
                let name = String(cString: sqlite3_column_name(stmt, i))
                row[name] = columnText(stmt, i) ?? ""
            }
            rows.append(row)
        }
        return rows
    }

    // MARK: - Internals

    private static func prepare(_ db: OpaquePointer?, sql: String) throws -> OpaquePointer {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK, let stmt else {
            throw RootstockBlueError.io("prepare failed: \(errmsg(db))")
        }
        return stmt
    }

    private static func bind(_ stmt: OpaquePointer, _ bindings: [SQLiteBindValue]) throws {
        for (index, value) in bindings.enumerated() {
            let i = Int32(index + 1)
            let rc: Int32
            switch value {
            case .null:
                rc = sqlite3_bind_null(stmt, i)
            case .int(let v):
                rc = sqlite3_bind_int64(stmt, i, v)
            case .double(let v):
                rc = sqlite3_bind_double(stmt, i, v)
            case .text(let v):
                rc = sqlite3_bind_text(stmt, i, v, -1, SQLITE_TRANSIENT)
            case .blob(let data):
                rc = data.withUnsafeBytes { raw in
                    sqlite3_bind_blob(stmt, i, raw.baseAddress, Int32(data.count), SQLITE_TRANSIENT)
                }
            }
            guard rc == SQLITE_OK else {
                throw RootstockBlueError.io("bind failed at index \(i)")
            }
        }
    }

    private static func columnText(_ stmt: OpaquePointer, _ index: Int32) -> String? {
        guard let c = sqlite3_column_text(stmt, index) else { return nil }
        return String(cString: c)
    }
}

/// SQLITE_TRANSIENT destructor: SQLite copies the bound buffer.
private let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
