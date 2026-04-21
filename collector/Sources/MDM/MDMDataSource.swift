import Foundation
import Models

/// Collects installed MDM configuration profiles and TCC policies they enforce.
public struct MDMDataSource: DataSource {
    public var name: String { "MDM" }

    /// Profile listing via `profiles -C` does not require elevation.
    public var requiresElevation: Bool { false }

    public init() { }

    public func collect() async -> DataSourceResult {
        let scanner = MDMProfileScanner()
        let (profiles, errors) = scanner.scan()

        let collectionErrors = errors.map {
            CollectionError(source: "MDM", message: $0, recoverable: true)
        }

        return DataSourceResult(nodes: profiles, errors: collectionErrors)
    }
}
