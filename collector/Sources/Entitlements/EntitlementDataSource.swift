import Foundation
import Models

/// Discovers installed apps and extracts their entitlements.
public struct EntitlementDataSource: DataSource {
    public let name = "Entitlements"
    public let requiresElevation = false

    private let discovery: AppDiscovery
    private let extractor: EntitlementExtractor
    private let classifier: EntitlementClassifier

    public init() {
        discovery = AppDiscovery()
        extractor = EntitlementExtractor()
        classifier = EntitlementClassifier()
    }

    /// Maximum number of apps processed concurrently.
    /// Balances parallelism against Security.framework / I/O contention.
    private static let maxConcurrency = 8

    public func collect() async -> DataSourceResult {
        let discovered = discovery.discover()
        guard !discovered.isEmpty else {
            return DataSourceResult(nodes: [], errors: [])
        }

        // Process apps in parallel with bounded concurrency.
        // Pattern: maintain a sliding window of at most `maxConcurrency` in-flight tasks.
        var applications: [Application] = []
        applications.reserveCapacity(discovered.count)

        let ext = extractor
        let cls = classifier

        await withTaskGroup(of: Application.self) { group in
            var iterator = discovered.makeIterator()
            var inFlight = 0

            // Seed initial tasks up to the concurrency limit
            while inFlight < Self.maxConcurrency, let app = iterator.next() {
                group.addTask { Self.processApp(app, extractor: ext, classifier: cls) }
                inFlight += 1
            }

            // Drain the group, adding the next app each time one completes
            for await result in group {
                applications.append(result)
                inFlight -= 1
                if let next = iterator.next() {
                    group.addTask { Self.processApp(next, extractor: ext, classifier: cls) }
                    inFlight += 1
                }
            }
        }

        var errors: [CollectionError] = []
        if !applications.isEmpty && applications.allSatisfy({ $0.entitlements.isEmpty }) {
            errors.append(CollectionError(
                source: name,
                message: "All \(applications.count) apps returned zero entitlements — codesign may not be working",
                recoverable: true
            ))
        }
        return DataSourceResult(nodes: applications, errors: errors)
    }

    private static func processApp(
        _ app: DiscoveredApp,
        extractor: EntitlementExtractor,
        classifier: EntitlementClassifier
    ) -> Application {
        let entitlementDict = extractor.extract(from: URL(fileURLWithPath: app.executablePath))
        let entitlements = classifier.classify(entitlementDict)
        let sandbox = classifier.analyzeSandbox(entitlementDict)
        return Application(
            name: app.name,
            bundleId: app.bundleId,
            path: app.path,
            version: app.version,
            teamId: nil,
            hardenedRuntime: false,
            libraryValidation: false,
            isElectron: app.isElectron,
            isSystem: app.isSystem,
            signed: false,  // pessimistic default; CodeSigningDataSource.enrich() sets the real value
            isSandboxed: sandbox.isSandboxed,
            sandboxExceptions: sandbox.exceptions,
            entitlements: entitlements,
            injectionMethods: []  // populated by CodeSigningDataSource
        )
    }
}
