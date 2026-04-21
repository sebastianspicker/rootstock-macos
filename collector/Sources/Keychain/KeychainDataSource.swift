import Foundation
import Models

/// Collects Keychain item metadata from the user login keychain.
///
/// This data source reads ONLY metadata (labels, services, access groups, trusted app lists).
/// Secret values (passwords, keys, certificates data) are never accessed.
public struct KeychainDataSource: DataSource {
    public var name: String { "Keychain" }

    /// System keychain requires root; user login keychain is accessible when unlocked.
    public var requiresElevation: Bool { false }

    public init() { }

    public func collect() async -> DataSourceResult {
        let scanner = KeychainScanner()
        let (items, errors) = scanner.scan()

        let collectionErrors = errors.map {
            CollectionError(source: "Keychain", message: $0, recoverable: true)
        }

        return DataSourceResult(nodes: items, errors: collectionErrors)
    }
}
