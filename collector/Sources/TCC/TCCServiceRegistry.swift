import Foundation
import RootstockMacFacts

/// Maps TCC service identifiers to human-readable display names.
///
/// Backed by the shared `TCCServiceCatalog` in RootstockMacFacts so red/blue
/// and collector stay on one vocabulary. Services are annotated with the
/// minimum macOS major version in which they were introduced. Unknown services
/// fall back to the raw identifier string.
enum TCCServiceRegistry {

    // MARK: - API

    /// Returns the display name for a TCC service identifier.
    /// Falls back to the raw service identifier for unknown services.
    static func displayName(for service: String) -> String {
        TCCServiceCatalog.displayName(for: service)
    }

    /// Returns the minimum macOS major version in which `service` was introduced,
    /// or nil if the service predates macOS 11 or is unknown.
    static func minimumMajorVersion(for service: String) -> Int? {
        TCCServiceCatalog.minimumMajorVersion(for: service)
    }

    /// Returns true if `service` has a known display name.
    static func isKnown(_ service: String) -> Bool {
        TCCServiceCatalog.isKnown(service)
    }

    /// Shared minimum-version table (for tests / call sites that read the map).
    static var minimumMajorVersions: [String: Int] {
        TCCServiceCatalog.minimumMajorVersions
    }
}
