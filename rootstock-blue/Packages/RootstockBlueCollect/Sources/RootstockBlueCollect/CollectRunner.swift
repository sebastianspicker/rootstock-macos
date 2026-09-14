import Darwin
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
        try run(
            pack: pack,
            sourceRoot: sourceRoot,
            into: package,
            actor: actor,
            afterSourceFileOpen: nil
        )
    }

    /// Internal synchronization seam for regression coverage. The hook runs
    /// only after `openat` has anchored the regular source file descriptor.
    func run(
        pack: CollectionPack,
        sourceRoot: URL,
        into package: CasePackage,
        actor: String = NSUserName(),
        afterSourceFileOpen: ((String) throws -> Void)?
    ) throws -> Result {
        let preflight = Preflight.check(for: pack, offlineFixtureMode: skipStrictPreflight)
        if !skipStrictPreflight {
            try Preflight.enforce(preflight)
        }

        let collection = try Self.collectArtifactEvents(
            pack: pack,
            sourceRoot: try Self.validatedSourceRoot(sourceRoot),
            package: package,
            afterSourceFileOpen: afterSourceFileOpen
        )
        let events = collection.events + [Self.summaryEvent(for: pack, filesCopied: collection.filesCopied)]
        try CaseEventSink(package: package, actor: actor).append(
            events,
            custody: EventCustodyNote(
                action: "collect",
                detail: "pack=\(pack.name) files=\(collection.filesCopied) events=\(events.count) root=\(sourceRoot.path)"
            )
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
        package: CasePackage,
        afterSourceFileOpen: ((String) throws -> Void)?
    ) throws -> (filesCopied: Int, events: [EventEnvelope]) {
        var filesCopied = 0
        var events: [EventEnvelope] = []
        var plannedPaths = Set<String>()

        for artifact in pack.artifacts {
            for relativePath in artifactPaths(for: artifact) {
                guard plannedPaths.insert(relativePath).inserted else { continue }
                guard let source = try openValidatedSourceFile(
                    relativePath: relativePath,
                    under: sourceRoot
                ) else { continue }
                defer { _ = close(source.descriptor) }
                try afterSourceFileOpen?(relativePath)
                let destinationName = "\(pack.name)/\(relativePath)"
                _ = try package.copyArtifact(
                    fromFileDescriptor: source.descriptor,
                    relativeName: destinationName
                )
                filesCopied += 1
                events.append(artifactEvent(
                    pack: pack,
                    artifact: artifact,
                    sourceURL: source.url,
                    relativePath: relativePath,
                    destinationName: destinationName
                ))
            }
        }
        return (filesCopied, events)
    }

    /// Normalizes a collection root once, then refuses roots reached through a
    /// link. The equality check includes ancestor links, not only a link at the
    /// final root component.
    private static func validatedSourceRoot(_ sourceRoot: URL) throws -> URL {
        let supplied = sourceRoot.standardizedFileURL
        let canonical = supplied.resolvingSymlinksInPath().standardizedFileURL
        guard supplied.path == canonical.path else {
            throw RootstockBlueError.io("collection source root must be canonical and not use symbolic links")
        }
        try requireDirectory(supplied, label: "collection source root")
        return canonical
    }

    /// Opens each component relative to a root directory descriptor. `openat`
    /// plus `O_NOFOLLOW` prevents a post-validation parent swap from changing
    /// the source read by CasePackage.
    private static func openValidatedSourceFile(relativePath: String, under root: URL) throws -> (descriptor: Int32, url: URL)? {
        let components = try validatedArtifactComponents(relativePath)
        guard let parent = try openArtifactParent(components: components, under: root) else { return nil }
        defer { _ = close(parent.descriptor) }
        return try openRegularArtifact(
            name: String(components.last!), parent: parent, root: root
        )
    }

    private static func validatedArtifactComponents(_ relativePath: String) throws -> [Substring] {
        let components = relativePath.split(separator: "/", omittingEmptySubsequences: false)
        guard !relativePath.isEmpty,
              !relativePath.hasPrefix("/"),
              components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." })
        else {
            throw RootstockBlueError.io("collection artifact path must be a safe relative path")
        }
        return components
    }

    private static func openArtifactParent(
        components: [Substring], under root: URL
    ) throws -> (descriptor: Int32, url: URL)? {
        var descriptor = try openCollectionRoot(root)
        var candidate = root
        for component in components.dropLast() {
            let name = String(component)
            let next = openat(descriptor, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
            guard next >= 0 else {
                _ = close(descriptor)
                if errno == ENOENT { return nil }
                throw RootstockBlueError.io("collection source contains an unsafe path component: \(candidate.appendingPathComponent(name).path)")
            }
            _ = close(descriptor)
            descriptor = next
            candidate.appendPathComponent(name, isDirectory: true)
        }
        return (descriptor, candidate)
    }

    private static func openCollectionRoot(_ root: URL) throws -> Int32 {
        let descriptor = open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard descriptor >= 0 else {
            throw RootstockBlueError.io("cannot open collection source root without following links")
        }
        return descriptor
    }

    private static func openRegularArtifact(
        name: String, parent: (descriptor: Int32, url: URL), root: URL
    ) throws -> (descriptor: Int32, url: URL)? {
        let fileDescriptor = openat(parent.descriptor, name, O_RDONLY | O_NOFOLLOW)
        guard fileDescriptor >= 0 else {
            if errno == ENOENT { return nil }
            throw RootstockBlueError.io("collection source contains an unsafe artifact path: \(parent.url.appendingPathComponent(name).path)")
        }
        do {
            try requireRegularArtifact(fileDescriptor, path: parent.url.appendingPathComponent(name).path)
            let url = parent.url.appendingPathComponent(name).standardizedFileURL
            guard url.path.hasPrefix(root.path + "/") else {
                throw RootstockBlueError.io("collection artifact escapes source root")
            }
            return (fileDescriptor, url)
        } catch {
            _ = close(fileDescriptor)
            throw error
        }
    }

    private static func requireRegularArtifact(_ descriptor: Int32, path: String) throws {
        var info = stat()
        guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else {
            throw RootstockBlueError.io("collection source path is not a real regular file: \(path)")
        }
    }

    private enum SourceNodeType {
        case regularFile
        case directory
        case symbolicLink
        case other
    }

    private static func requireDirectory(_ url: URL, label: String) throws {
        guard try nodeTypeIfPresent(at: url) == .directory else {
            throw RootstockBlueError.io("\(label) must be a real directory")
        }
    }

    private static func nodeTypeIfPresent(at url: URL) throws -> SourceNodeType? {
        var info = stat()
        guard lstat(url.path, &info) == 0 else {
            if errno == ENOENT { return nil }
            throw RootstockBlueError.io("cannot inspect collection source path: \(url.path)")
        }
        switch info.st_mode & S_IFMT {
        case S_IFREG: return .regularFile
        case S_IFDIR: return .directory
        case S_IFLNK: return .symbolicLink
        default: return .other
        }
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

    /// Map logical artifact names to relative paths under a macOS-like tree.
    private static let artifactPathGroups = coreArtifactPathGroups + persistenceArtifactPathGroups + residualArtifactPathGroups

    public static func artifactPaths(for name: String) -> [String] {
        let normalizedName = name.lowercased()
        return artifactPathGroups.first { $0.names.contains(normalizedName) }?.paths ?? [name]
    }
}
