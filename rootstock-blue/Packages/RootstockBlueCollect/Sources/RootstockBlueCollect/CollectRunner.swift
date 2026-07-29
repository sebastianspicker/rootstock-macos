import Foundation
import RootstockBlueCore
import RootstockBlueCase

/// Executes collection packs against a host path or fixture tree, writing into a case.
/// Preflight is reported honestly; for offline fixture trees, use `skipStrictPreflight: true`.
public struct CollectRunner: Sendable {
    public var skipStrictPreflight: Bool

    public init(skipStrictPreflight: Bool = false) {
        self.skipStrictPreflight = skipStrictPreflight
    }

    public struct Result: Sendable {
        public var packName: String
        public var filesCopied: Int
        public var eventsWritten: Int
        public var preflight: PreflightReport
    }

    public func run(
        pack: CollectionPack,
        sourceRoot: URL,
        into package: CasePackage,
        actor: String = NSUserName()
    ) throws -> Result {
        let preflight = Preflight.check(for: pack, offlineFixtureMode: skipStrictPreflight)
        if !skipStrictPreflight {
            try Preflight.enforce(preflight)
        }

        let collection = try Self.collectArtifactEvents(
            pack: pack,
            sourceRoot: sourceRoot,
            package: package
        )
        let events = collection.events + [Self.summaryEvent(for: pack, filesCopied: collection.filesCopied)]
        try Self.record(events, in: package, actor: actor)
        try CaseEventSink(package: package, actor: actor).noteCustody(
            action: "collect",
            detail: "pack=\(pack.name) files=\(collection.filesCopied) events=\(events.count) root=\(sourceRoot.path)"
        )

        return Result(
            packName: pack.name,
            filesCopied: collection.filesCopied,
            eventsWritten: events.count,
            preflight: preflight
        )
    }

    private static func collectArtifactEvents(
        pack: CollectionPack,
        sourceRoot: URL,
        package: CasePackage
    ) throws -> (filesCopied: Int, events: [EventEnvelope]) {
        let fileManager = FileManager.default
        var filesCopied = 0
        var events: [EventEnvelope] = []

        for artifact in pack.artifacts {
            for relativePath in artifactPaths(for: artifact) {
                let sourceURL = sourceRoot.appendingPathComponent(relativePath)
                guard fileManager.fileExists(atPath: sourceURL.path) else { continue }
                let destinationName = "\(pack.name)/\(relativePath)"
                _ = try package.copyArtifact(from: sourceURL, relativeName: destinationName)
                filesCopied += 1
                events.append(artifactEvent(
                    pack: pack,
                    artifact: artifact,
                    sourceURL: sourceURL,
                    relativePath: relativePath,
                    destinationName: destinationName
                ))
            }
        }
        return (filesCopied, events)
    }

    private static func artifactEvent(
        pack: CollectionPack,
        artifact: String,
        sourceURL: URL,
        relativePath: String,
        destinationName: String
    ) -> EventEnvelope {
        EventEnvelope(
            identity: .init(kind: "collect.artifact", label: "collect.\(pack.name)"),
            capture: .init(source: .collect),
            payload: .init(entityRefs: [.file(path: destinationName)], properties: [
                "collect.pack": pack.name,
                "collect.artifact": artifact,
                "collect.source_path": sourceURL.path,
                "collect.relative": relativePath,
                FieldTaxonomy.filePath: destinationName,
                FieldTaxonomy.eventType: "collect.artifact",
            ], provenance: sourceURL.path,
            confidence: 1.0
            )
        )
    }

    private static func summaryEvent(for pack: CollectionPack, filesCopied: Int) -> EventEnvelope {
        EventEnvelope(
            identity: .init(kind: "collect.summary", label: "collect.\(pack.name)"),
            capture: .init(source: .collect),
            payload: .init(entityRefs: [], properties: [
                "collect.pack": pack.name,
                "collect.files_copied": String(filesCopied),
                "collect.artifact_count": String(pack.artifacts.count),
                FieldTaxonomy.eventType: "collect.summary",
            ],
            confidence: 1.0
            )
        )
    }

    private static func record(_ events: [EventEnvelope], in package: CasePackage, actor: String) throws {
        let sink = CaseEventSink(package: package, actor: actor)
        for event in events {
            try sink.append(event)
        }
    }

    /// Map logical artifact names to relative paths under a macOS-like tree.
    private static let artifactPathGroups = coreArtifactPathGroups + persistenceArtifactPathGroups + residualArtifactPathGroups

    public static func artifactPaths(for name: String) -> [String] {
        let normalizedName = name.lowercased()
        return artifactPathGroups.first { $0.names.contains(normalizedName) }?.paths ?? [name]
    }
}
