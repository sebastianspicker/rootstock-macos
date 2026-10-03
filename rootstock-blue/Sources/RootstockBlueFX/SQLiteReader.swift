import Foundation
import SQLite3
import RootstockBlueCore
#if canImport(Darwin)
import Darwin
#endif

/// Minimal read-only SQLite helper for offline artifact DBs.
///
/// Not `Sendable`: exclusive ownership of the C handle. Use on a single isolation domain.
/// Dynamic values are bound via `SQLiteBindValue` - never spliced into SQL text.
public final class SQLiteReader {
    private var db: OpaquePointer?

    public init(url: URL, readonly: Bool = true) throws {
        if readonly {
            try Self.validateSidecars(for: url)
        }
        let flags = readonly
            ? SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX
            : SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX
        do {
            db = try SQLiteSupport.open(path: url.path, flags: flags)
        } catch {
            throw RootstockBlueError.io("sqlite open failed for \(url.lastPathComponent): \(error.localizedDescription)")
        }
    }

    /// SQLite may automatically open journal siblings. Refuse linked or special
    /// sidecars so a validated evidence database cannot redirect those reads.
    private static func validateSidecars(for url: URL) throws {
        for suffix in ["-wal", "-shm", "-journal"] {
            let path = url.path + suffix
            var info = stat()
            guard lstat(path, &info) == 0 else {
                if errno == ENOENT { continue }
                throw RootstockBlueError.io("cannot inspect SQLite sidecar for \(url.lastPathComponent)")
            }
            let type = info.st_mode & S_IFMT
            guard type == S_IFREG else {
                throw RootstockBlueError.io(
                    "SQLite sidecar must be a real regular file for \(url.lastPathComponent)"
                )
            }
        }
    }

    deinit {
        SQLiteSupport.close(db)
        db = nil
    }

    /// Returns rows as column-name → string value maps.
    /// Pass dynamic filters via `bindings` (`?` placeholders in `sql`).
    public func query(_ sql: String, bindings: [SQLiteBindValue] = []) throws -> [[String: String]] {
        try SQLiteSupport.queryRows(db, sql: sql, bindings: bindings)
    }

    public func tableExists(_ name: String) throws -> Bool {
        let rows = try query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=? LIMIT 1;",
            bindings: [.text(name)]
        )
        return !rows.isEmpty
    }
}
