import Foundation
import Models

// MARK: - Protocol

/// Adapts TCC database queries to the schema of a specific macOS version.
///
/// The TCC `access` table schema has been stable across macOS 14–26 for the
/// columns we need. However, Apple may add or reorganise columns in future
/// releases. This protocol lets each macOS-version-specific adapter declare
/// which columns it requires and how to parse rows — without scattering
/// `if macOS15 { }` branches throughout the reader.
///
/// New columns introduced by future macOS versions are detected via
/// `SQLiteDatabase.columnNames(table:)` and will be silently ignored by
/// existing adapters (forward-compatible by design).
protocol TCCSchemaAdapter {
    /// Column names that MUST exist in the access table for this adapter.
    /// If any required column is absent the factory returns nil.
    var requiredColumns: Set<String> { get }

    /// SQL SELECT statement (includes WHERE clause).
    /// The statement must project exactly the columns that `parseRow` expects.
    func buildQuery() -> String

    /// Parse a result row from `SQLiteDatabase.query(_:)` into a TCCGrant.
    /// Returns nil if the row is malformed (missing required fields).
    func parseRow(_ row: [String: Any], scope: String) -> TCCGrant?
}


// MARK: - Standard adapter (macOS 14–26)

/// TCC schema adapter for all currently supported macOS versions (14 Sonoma
/// through 26 Tahoe).
///
/// Queries the six columns that have been stable since macOS Catalina.
/// Any additional columns present in the database (e.g. `pid`, `boot_uuid`)
/// are intentionally ignored — we only read what we need.
///
/// The access-control differences between macOS versions (e.g. Sequoia's
/// kernel-level FDA requirement) are handled by `TCCDataSource`, not here.
/// If a future macOS version changes the `access` table schema, add a new
/// adapter conforming to `TCCSchemaAdapter` and register it in the factory.
struct StandardTCCSchemaAdapter: TCCSchemaAdapter {
    let requiredColumns: Set<String> = [
        "service", "client", "client_type",
        "auth_value", "auth_reason", "last_modified",
    ]

    func buildQuery() -> String {
        // auth_value semantics: 0=denied, 1=not_yet_prompted (excluded),
        // 2=allowed, 3=limited (allowed with restrictions).
        // We intentionally include denied grants (auth_value=0) for audit
        // visibility — the `allowed` property on TCCGrantData distinguishes
        // them from truly allowed grants.
        "SELECT service, client, client_type, auth_value, auth_reason, last_modified " +
        "FROM access WHERE auth_value != 1"
    }

    func parseRow(_ row: [String: Any], scope: String) -> TCCGrant? {
        guard
            let service     = row["service"]       as? String,
            let client      = row["client"]        as? String,
            let clientType  = row["client_type"]   as? Int,
            let authValue   = row["auth_value"]    as? Int,
            let authReason  = row["auth_reason"]   as? Int,
            let lastMod     = row["last_modified"] as? Int
        else { return nil }

        return TCCGrant(
            service: service,
            displayName: TCCServiceRegistry.displayName(for: service),
            client: client,
            clientType: clientType,
            authValue: authValue,
            authReason: authReason,
            scope: scope,
            lastModified: lastMod
        )
    }
}

// Type aliases preserve API compatibility for tests and existing references.
typealias SonomaTCCSchemaAdapter = StandardTCCSchemaAdapter
typealias SequoiaTCCSchemaAdapter = StandardTCCSchemaAdapter
typealias TahoeTCCSchemaAdapter = StandardTCCSchemaAdapter


// MARK: - Factory

/// Creates the appropriate `TCCSchemaAdapter` for a given macOS version and
/// database, using PRAGMA-based column introspection to validate compatibility.
enum TCCSchemaAdapterFactory {

    /// Build an adapter for `version`, validating that `db` has the required columns.
    ///
    /// Returns `nil` if the `access` table is missing or doesn't have all
    /// required columns (e.g. a deliberately malformed DB).
    static func make(
        for version: MacOSVersion,
        db: SQLiteDatabase
    ) -> (adapter: TCCSchemaAdapter, error: String?)? {
        let available = db.columnNames(table: "access")
        guard !available.isEmpty else {
            return nil  // no access table (malformed DB)
        }

        // All supported versions currently use the same schema adapter.
        // When Apple changes the schema, add a version-specific branch here.
        let candidate: TCCSchemaAdapter = StandardTCCSchemaAdapter()

        let missing = candidate.requiredColumns.subtracting(available)
        guard missing.isEmpty else {
            return nil  // schema incompatible (missing required columns)
        }

        return (candidate, nil)
    }
}
