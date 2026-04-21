import Foundation
import SQLite3

enum SQLiteError: Error, LocalizedError {
    case cannotOpen(path: String, message: String)
    case queryFailed(code: Int32, message: String)

    var errorDescription: String? {
        switch self {
        case .cannotOpen(let path, let message):
            return "Cannot open SQLite database at \(path): \(message)"
        case .queryFailed(let code, let message):
            return "SQLite query failed (code \(code)): \(message)"
        }
    }
}

/// Read-only wrapper around the C sqlite3 API.
/// Works transparently with WAL-mode databases (like TCC.db), which allows
/// reads to proceed concurrently with tccd writes.
final class SQLiteDatabase {
    private var db: OpaquePointer?

    init(path: String) throws {
        let rc = sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil)
        guard rc == SQLITE_OK else {
            let msg = db.flatMap { String(validatingUTF8: sqlite3_errmsg($0)) } ?? "unknown error"
            sqlite3_close(db)
            db = nil
            throw SQLiteError.cannotOpen(path: path, message: msg)
        }
        // Non-blocking retry for SQLITE_BUSY: SQLite internally retries for
        // up to 500ms when tccd holds a brief checkpoint lock.
        sqlite3_busy_timeout(db, 500)
    }

    deinit {
        sqlite3_close(db)
    }

    /// Return the column names of a table using PRAGMA table_info.
    /// Returns an empty set if the table doesn't exist or the DB can't be queried.
    func columnNames(table: String) -> Set<String> {
        // PRAGMA arguments cannot be parameterised; table name is caller-controlled.
        // Only called internally with the hardcoded literal "access".
        guard let rows = try? query("PRAGMA table_info(\(table))") else {
            return []
        }
        return Set(rows.compactMap { $0["name"] as? String })
    }

    /// Execute a SELECT query and return rows as dictionaries.
    /// Throws `SQLiteError.queryFailed` on prepare or step errors.
    func query(_ sql: String) throws -> [[String: Any]] {
        guard let db = db else {
            throw SQLiteError.queryFailed(code: SQLITE_MISUSE, message: "Database handle is nil")
        }

        var stmt: OpaquePointer?
        let prepareRC = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        guard prepareRC == SQLITE_OK else {
            let msg = String(validatingUTF8: sqlite3_errmsg(db)) ?? "unknown error"
            throw SQLiteError.queryFailed(code: prepareRC, message: msg)
        }
        defer { sqlite3_finalize(stmt) }

        var rows: [[String: Any]] = []
        while true {
            let stepRC = sqlite3_step(stmt)
            if stepRC == SQLITE_DONE {
                break
            }
            guard stepRC == SQLITE_ROW else {
                let msg = String(validatingUTF8: sqlite3_errmsg(db)) ?? "unknown error"
                throw SQLiteError.queryFailed(code: stepRC, message: msg)
            }
            var row: [String: Any] = [:]
            let columnCount = sqlite3_column_count(stmt)
            for i in 0..<columnCount {
                guard let rawName = sqlite3_column_name(stmt, i) else { continue }
                let name = String(cString: rawName)
                switch sqlite3_column_type(stmt, i) {
                case SQLITE_INTEGER:
                    row[name] = Int(sqlite3_column_int64(stmt, i))
                case SQLITE_FLOAT:
                    row[name] = sqlite3_column_double(stmt, i)
                case SQLITE_TEXT:
                    if let ptr = sqlite3_column_text(stmt, i) {
                        row[name] = String(cString: ptr)
                    }
                case SQLITE_BLOB:
                    let count = Int(sqlite3_column_bytes(stmt, i))
                    if count > 0, let ptr = sqlite3_column_blob(stmt, i) {
                        row[name] = Data(bytes: ptr, count: count)
                    }
                default:
                    break
                }
            }
            rows.append(row)
        }
        return rows
    }
}
