import Foundation
import Models

/// Reads TCC (Transparency, Consent, and Control) grants from macOS TCC databases.
///
/// Always attempts the user-level database. The system-level database requires
/// Full Disk Access — failure there is caught and logged, not fatal.
///
/// Schema compatibility is determined at runtime via PRAGMA-based column
/// introspection. The reader validates the stable columns it needs and ignores
/// any newer columns Apple adds to the `access` table.
public struct TCCDataSource: DataSource {
    public let name = "TCC Database"
    public let requiresElevation = false

    private static let requiredColumns: Set<String> = [
        "service", "client", "client_type",
        "auth_value", "auth_reason", "last_modified",
    ]

    private static let grantQuery =
        "SELECT service, client, client_type, auth_value, auth_reason, last_modified " +
        "FROM access WHERE auth_value != 1"

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

        guard Self.hasRequiredColumns(in: db) else {
            return ([], [CollectionError(
                source: name,
                message: "TCC database at \(path) has an incompatible schema " +
                         "(missing required columns). The database may be malformed.",
                recoverable: true
            )])
        }

        let rows: [[String: Any]]
        do {
            rows = try db.query(Self.grantQuery)
        } catch {
            return ([], [CollectionError(
                source: name,
                message: "TCC query failed for \(path): \(error.localizedDescription)",
                recoverable: true
            )])
        }
        var grants: [TCCGrant] = []
        for row in rows {
            if let grant = Self.parseGrant(row, scope: scope) {
                grants.append(grant)
            }
        }
        return (grants, [])
    }

    private static func hasRequiredColumns(in db: SQLiteDatabase) -> Bool {
        let available = db.columnNames(table: "access")
        return !available.isEmpty && requiredColumns.isSubset(of: available)
    }

    private static func parseGrant(_ row: [String: Any], scope: String) -> TCCGrant? {
        guard
            let service = row["service"] as? String,
            let client = row["client"] as? String,
            let clientType = row["client_type"] as? Int,
            let authValue = row["auth_value"] as? Int,
            let authReason = row["auth_reason"] as? Int,
            let lastModified = row["last_modified"] as? Int
        else { return nil }

        return TCCGrant(
            service: service,
            displayName: TCCServiceRegistry.displayName(for: service),
            client: client,
            clientType: clientType,
            authValue: authValue,
            authReason: authReason,
            scope: scope,
            lastModified: lastModified
        )
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

/// Probes whether the current process can open and query a TCC database.
public enum TCCAccessProbe {
    public static let systemDatabasePath = "/Library/Application Support/com.apple.TCC/TCC.db"

    public static func canQueryDatabase(at path: String) -> Bool {
        do {
            let db = try SQLiteDatabase(path: path)
            _ = try db.query("SELECT 1 FROM access LIMIT 1")
            return true
        } catch {
            return false
        }
    }

    public static func hasFullDiskAccess() -> Bool {
        canQueryDatabase(at: systemDatabasePath)
    }
}
