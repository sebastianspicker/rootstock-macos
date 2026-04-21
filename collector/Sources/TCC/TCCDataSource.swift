import Foundation
import Models

/// Reads TCC (Transparency, Consent, and Control) grants from macOS TCC databases.
///
/// Always attempts the user-level database. The system-level database requires
/// Full Disk Access — failure there is caught and logged, not fatal.
///
/// Schema compatibility is determined at runtime via PRAGMA-based column
/// introspection (`TCCSchemaAdapterFactory`), so the reader is forward-compatible
/// with future macOS versions that add new columns to the `access` table.
public struct TCCDataSource: DataSource {
    public let name = "TCC Database"
    public let requiresElevation = false

    let userDBPath: String
    let systemDBPath: String?
    let macOSVersion: MacOSVersion

    /// Default initializer — uses the standard macOS TCC database paths.
    public init() {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        userDBPath = home + "/Library/Application Support/com.apple.TCC/TCC.db"
        systemDBPath = "/Library/Application Support/com.apple.TCC/TCC.db"
        macOSVersion = MacOSVersion.detect()
    }

    /// Testable initializer with injectable paths and optional version override.
    init(userDBPath: String, systemDBPath: String?, macOSVersion: MacOSVersion = MacOSVersion.detect()) {
        self.userDBPath = userDBPath
        self.systemDBPath = systemDBPath
        self.macOSVersion = macOSVersion
    }

    public func collect() async -> DataSourceResult {
        var grants: [TCCGrant] = []
        var errors: [CollectionError] = []

        let userResult = readDB(at: userDBPath, scope: "user")
        grants.append(contentsOf: userResult.grants)
        errors.append(contentsOf: userResult.errors)

        if let systemPath = systemDBPath {
            let systemResult = readDB(at: systemPath, scope: "system")
            grants.append(contentsOf: systemResult.grants)
            errors.append(contentsOf: systemResult.errors)
        }

        return DataSourceResult(nodes: grants, errors: errors)
    }

    private func readDB(at path: String, scope: String) -> (grants: [TCCGrant], errors: [CollectionError]) {
        let db: SQLiteDatabase
        do {
            db = try SQLiteDatabase(path: path)
        } catch {
            return ([], [CollectionError(
                source: name,
                message: accessErrorMessage(for: error, path: path),
                recoverable: true
            )])
        }

        guard let result = TCCSchemaAdapterFactory.make(for: macOSVersion, db: db) else {
            return ([], [CollectionError(
                source: name,
                message: "TCC database at \(path) has an incompatible schema " +
                         "(missing required columns). The database may be malformed.",
                recoverable: true
            )])
        }

        let rows: [[String: Any]]
        do {
            rows = try db.query(result.adapter.buildQuery())
        } catch {
            return ([], [CollectionError(
                source: name,
                message: "TCC query failed for \(path): \(error.localizedDescription)",
                recoverable: true
            )])
        }
        var grants: [TCCGrant] = []
        for row in rows {
            if let grant = result.adapter.parseRow(row, scope: scope) {
                grants.append(grant)
            }
        }
        return (grants, [])
    }

    /// Returns a macOS-version-aware error message for open/auth failures.
    private func accessErrorMessage(for error: Error, path: String) -> String {
        let base = error.localizedDescription
        switch macOSVersion {
        case .sequoia, .tahoe:
            return "\(base). On \(macOSVersion.displayString), TCC.db requires " +
                   "Full Disk Access. Grant FDA to the binary or run with sudo."
        default:
            return base
        }
    }
}
