import Foundation
import Models
import HostCommand

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

    private struct ProcessedApp: Sendable {
        let application: Application
        let error: CollectionError?
    }

    public func collect() async -> DataSourceResult {
        let discoveryResult = discovery.discover()
        let discovered = discoveryResult.applications
        var errors = discoveryResult.errors
        guard !discovered.isEmpty else {
            return DataSourceResult(nodes: [], errors: errors)
        }

        // Process apps in parallel with bounded concurrency.
        // Pattern: maintain a sliding window of at most `maxConcurrency` in-flight tasks.
        var applications: [Application] = []
        applications.reserveCapacity(discovered.count)

        let ext = extractor
        let cls = classifier

        await withTaskGroup(of: ProcessedApp.self) { group in
            var iterator = discovered.makeIterator()
            var inFlight = 0

            // Seed initial tasks up to the concurrency limit
            while inFlight < Self.maxConcurrency, let app = iterator.next() {
                group.addTask { Self.processApp(app, extractor: ext, classifier: cls) }
                inFlight += 1
            }

            // Drain the group, adding the next app each time one completes
            for await result in group {
                applications.append(result.application)
                if let error = result.error {
                    errors.append(error)
                }
                inFlight -= 1
                if let next = iterator.next() {
                    group.addTask { Self.processApp(next, extractor: ext, classifier: cls) }
                    inFlight += 1
                }
            }
        }

        // Task-group completion order is nondeterministic; sort for stable output.
        applications.sort { ($0.path, $0.bundleId) < ($1.path, $1.bundleId) }
        errors.sort { $0.message < $1.message }

        let appsWithKnownEntitlements = applications.filter(\.entitlementsAvailable)
        if !appsWithKnownEntitlements.isEmpty && appsWithKnownEntitlements.allSatisfy({ $0.entitlements.isEmpty }) {
            errors.append(CollectionError(
                source: name,
                message: "All \(applications.count) apps returned zero entitlements - codesign may not be working",
                recoverable: true
            ))
        }
        return DataSourceResult(nodes: applications, errors: errors)
    }

    private static func processApp(
        _ app: DiscoveredApp,
        extractor: EntitlementExtractor,
        classifier: EntitlementClassifier
    ) -> ProcessedApp {
        let extraction = app.executablePath.map { extractor.extract(from: URL(fileURLWithPath: $0)) }
            ?? EntitlementExtractionResult(
                entitlements: [:],
                available: false,
                errorMessage: "Bundle executable name is not a plain file name"
            )
        let entitlementDict = extraction.entitlements
        let entitlements = classifier.classify(entitlementDict)
        let sandbox = classifier.analyzeSandbox(entitlementDict)
        // AppDiscovery already reported bundles whose executable name was rejected.
        let error = extraction.available || app.executablePath == nil ? nil : CollectionError(
            source: "Entitlements",
            message: "Failed to extract entitlements for \(app.bundleId): \(extraction.errorMessage ?? "unknown error")",
            recoverable: true
        )
        let application = Application(
            identity: Application.Identity(
                name: app.name,
                bundleId: app.bundleId,
                path: app.path,
                version: app.version,
                executablePath: app.executablePath,
                executableSha256: executableDigest(for: app)
            ),
            flags: Application.Flags(
                isElectron: app.isElectron,
                isSystem: app.isSystem,
                electronRunAsNode: app.electronRunAsNode
            ),
            signing: Application.Signing(signed: nil),  // CodeSigningDataSource.enrich() sets the real value.
            security: Application.Security(
                isSandboxed: sandbox.isSandboxed,
                sandboxExceptions: sandbox.exceptions
            ),
            entitlementState: Application.EntitlementState(
                entitlementsAvailable: extraction.available,
                entitlementExtractionError: extraction.errorMessage,
                entitlements: entitlements,
                injectionMethods: []  // populated by CodeSigningDataSource
            )
        )
        return ProcessedApp(application: application, error: error)
    }

    /// SHA-256 of a third-party app's main executable; Apple and `/System/` apps are skipped.
    private static func executableDigest(for app: DiscoveredApp) -> String? {
        guard let executablePath = app.executablePath, !app.isSystem, !app.path.hasPrefix("/System/"),
              !executablePath.hasPrefix("/System/") else {
            return nil
        }
        return FileDigest.sha256(ofFileAt: executablePath)
    }
}
