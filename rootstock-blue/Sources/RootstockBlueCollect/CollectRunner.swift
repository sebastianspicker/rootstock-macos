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
                    + " skipped=\(collection.skipped)" + collection.notes.prefix(Self.maxCustodyNotes).map { " note=\($0)" }.joined()
                + (collection.notes.count > Self.maxCustodyNotes ? " notes_omitted=\(collection.notes.count - Self.maxCustodyNotes)" : "")
            )
        )

        return Result(
            packName: pack.name,
            filesCopied: collection.filesCopied,
            eventsWritten: events.count,
            preflight: preflight
        )
    }

    private static let maxWalkDepth = 8
    private static let maxWalkFiles = 10_000
    private static let maxFileBytes: off_t = 4 << 30
    private static let maxCustodyNotes = 100

    private struct Walk {
        var files: [String] = []
        var skipped = 0
        var notes: [String] = []
        /// `files.count` when the current requested path started: the file cap is per path.
        var capBase = 0

        /// Plans a regular file unless it is a credential store or too large to copy.
        mutating func plan(_ path: String, name: String, size: off_t) {
            if CollectRunner.isCredentialStore(name) {
                notes.append("credential file withheld: \(path)")
            } else if size > CollectRunner.maxFileBytes {
                notes.append("file larger than \(CollectRunner.maxFileBytes) bytes skipped: \(path)")
            } else {
                files.append(path)
                return
            }
            skipped += 1
        }
    }

    private static func collectArtifactEvents(
        pack: CollectionPack,
        sourceRoot: URL,
        package: CasePackage,
        afterSourceFileOpen: ((String) throws -> Void)?
    ) throws -> (filesCopied: Int, events: [EventEnvelope], skipped: Int, notes: [String]) {
        var walk = Walk()
        let planned = try planArtifacts(pack: pack, sourceRoot: sourceRoot, into: &walk)

        // Sources are opened one at a time inside the batch so a large folder cannot exhaust
        // descriptors. A source that changed or vanished since planning is skipped, never followed.
        let items = planned.map { entry in
            CasePackage.ArtifactCopy(
                relativeName: "\(pack.name)/\(entry.relativePath)",
                sourceDescription: sourceRoot.appendingPathComponent(entry.relativePath).path
            ) {
                guard let source = try? openValidatedSourceFile(relativePath: entry.relativePath, under: sourceRoot) else {
                    return nil
                }
                do {
                    try afterSourceFileOpen?(entry.relativePath)
                } catch {
                    _ = close(source.descriptor)
                    throw error
                }
                return source.descriptor
            }
        }
        let copied = try package.copyArtifacts(items)

        var events: [EventEnvelope] = []
        for (entry, destination) in zip(planned, copied) {
            guard destination != nil else {
                walk.skipped += 1
                walk.notes.append("changed or vanished after planning, not copied: \(entry.relativePath)")
                continue
            }
            events.append(artifactEvent(
                pack: pack,
                artifact: entry.artifact,
                sourceURL: sourceRoot.appendingPathComponent(entry.relativePath).standardizedFileURL,
                relativePath: entry.relativePath,
                destinationName: "\(pack.name)/\(entry.relativePath)"
            ))
        }
        return (events.count, events, walk.skipped, walk.notes)
    }

    /// Every file the pack asks for, each once. A case-insensitive case volume cannot hold
    /// two names that differ only in case, so the second one is recorded and skipped.
    private static func planArtifacts(
        pack: CollectionPack,
        sourceRoot: URL,
        into walk: inout Walk
    ) throws -> [(artifact: String, relativePath: String)] {
        var planned: [(artifact: String, relativePath: String)] = []
        var plannedPaths = Set<String>()
        var foldedPaths = Set<String>()
        var requestedPaths = Set<String>()
        let users = try userFolderNames(under: sourceRoot, into: &walk)
        let requests = pack.artifacts.flatMap { artifact in
            expandedArtifactPaths(for: artifact, users: users).map { (artifact, $0) }
        }
        for (artifact, requested) in requests where requestedPaths.insert(requested).inserted {
            walk.capBase = walk.files.count
            try planFiles(relativePath: requested, under: sourceRoot, into: &walk)
            for file in walk.files[walk.capBase...] where plannedPaths.insert(file).inserted {
                guard foldedPaths.insert(file.lowercased()).inserted else {
                    walk.skipped += 1
                    walk.notes.append("name differs from another only by case, not copied: \(file)")
                    continue
                }
                planned.append((artifact, file))
            }
        }
        return planned
    }

    /// Expands `Users/*/` over the user folders of the source tree.
    private static func expandedArtifactPaths(for artifact: String, users: [String]) -> [String] {
        let wildcard = "Users/*/"
        return artifactPaths(for: artifact).flatMap { path in
            path.hasPrefix(wildcard) ? users.map { "Users/\($0)/" + path.dropFirst(wildcard.count) } : [path]
        }
    }

    /// Real user folders, hidden ones included (a hidden account is a persistence technique).
    /// `Shared` is not a user; links and other node types are recorded, never followed.
    private static func userFolderNames(under root: URL, into walk: inout Walk) throws -> [String] {
        let rootDescriptor = try openCollectionRoot(root)
        defer { _ = close(rootDescriptor) }
        let usersDescriptor = openat(rootDescriptor, "Users", O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard usersDescriptor >= 0 else { return [] }
        defer { _ = close(usersDescriptor) }
        return try directoryEntryNames(usersDescriptor).filter { name in
            guard name != "Shared" else { return false }
            var info = stat()
            if fstatat(usersDescriptor, name, &info, AT_SYMLINK_NOFOLLOW) == 0, (info.st_mode & S_IFMT) == S_IFDIR {
                return true
            }
            // Dot files such as `.localized` are not accounts; hidden folders still are.
            if name.hasPrefix(".") { return false }
            walk.skipped += 1
            walk.notes.append("user entry is not a real folder, not collected: Users/\(name)")
            return false
        }
    }

    private static func directoryEntryNames(_ descriptor: Int32) throws -> [String] {
        let duplicate = dup(descriptor)
        guard duplicate >= 0, let stream = fdopendir(duplicate) else {
            if duplicate >= 0 { _ = close(duplicate) }
            throw RootstockBlueError.io("cannot read collection source directory")
        }
        defer { closedir(stream) }
        var names: [String] = []
        while let entry = readdir(stream) {
            let name = withUnsafeBytes(of: entry.pointee.d_name) { String(cString: $0.bindMemory(to: CChar.self).baseAddress!) }
            if name != "." && name != ".." { names.append(name) }
        }
        return names.sorted()
    }

    /// Lists the files to copy for one artifact path. A missing path plans nothing, a
    /// directory is walked, a regular file is planned, and links or special files are
    /// recorded as skipped (never followed). A link in a parent component still throws
    /// before anything is copied.
    private static func planFiles(relativePath: String, under root: URL, into walk: inout Walk) throws {
        let components = try validatedArtifactComponents(relativePath)
        guard let parent = try planningParent(components: components, under: root, into: &walk) else { return }
        defer { _ = close(parent.descriptor) }
        let name = String(components.last!)
        var info = stat()
        guard fstatat(parent.descriptor, name, &info, AT_SYMLINK_NOFOLLOW) == 0 else {
            if errno == ENOENT { return }
            throw RootstockBlueError.io("collection source contains an unsafe artifact path: \(parent.url.appendingPathComponent(name).path)")
        }
        switch info.st_mode & S_IFMT {
        case S_IFREG:
            walk.plan(relativePath, name: name, size: info.st_size)
        case S_IFDIR:
            let directory = openat(parent.descriptor, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
            guard directory >= 0 else {
                throw RootstockBlueError.io("collection source contains an unsafe artifact path: \(parent.url.appendingPathComponent(name).path)")
            }
            defer { _ = close(directory) }
            try walkDirectory(directory, prefix: relativePath, depth: 0, into: &walk)
        default:
            walk.skipped += 1
            walk.notes.append("not a regular file or folder, not collected: \(relativePath)")
        }
    }

    /// The opened parent folder, or nil when it is missing or not readable (recorded, not fatal).
    private static func planningParent(
        components: [Substring], under root: URL, into walk: inout Walk
    ) throws -> (descriptor: Int32, url: URL)? {
        switch try openArtifactParent(components: components, under: root) {
        case .missing:
            return nil
        case .unreadable(let path):
            walk.skipped += 1
            walk.notes.append("folder not readable, not collected: \(path)")
            return nil
        case .notFollowed(let path):
            walk.skipped += 1
            walk.notes.append("link not followed: \(path)")
            return nil
        case .opened(let descriptor, let url):
            return (descriptor, url)
        }
    }

    /// Children are classified with `fstatat(AT_SYMLINK_NOFOLLOW)` and subfolders opened with
    /// `openat(O_NOFOLLOW)` relative to the parent descriptor. Links and special files are skipped.
    private static func walkDirectory(_ descriptor: Int32, prefix: String, depth: Int, into walk: inout Walk) throws {
        for name in try directoryEntryNames(descriptor) {
            guard walk.files.count - walk.capBase < maxWalkFiles else {
                walk.notes.append("file limit \(maxWalkFiles) reached under \(prefix)")
                return
            }
            var info = stat()
            guard fstatat(descriptor, name, &info, AT_SYMLINK_NOFOLLOW) == 0 else {
                walk.skipped += 1
                continue
            }
            switch info.st_mode & S_IFMT {
            case S_IFREG:
                walk.plan("\(prefix)/\(name)", name: name, size: info.st_size)
            case S_IFDIR:
                guard depth < maxWalkDepth else {
                    walk.notes.append("depth limit \(maxWalkDepth) reached at \(prefix)/\(name)")
                    continue
                }
                let child = openat(descriptor, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
                guard child >= 0 else {
                    walk.skipped += 1
                    continue
                }
                defer { _ = close(child) }
                try walkDirectory(child, prefix: "\(prefix)/\(name)", depth: depth + 1, into: &walk)
            default:
                walk.skipped += 1
            }
        }
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
        guard case .opened(let parentDescriptor, let parentURL) = try openArtifactParent(components: components, under: root) else {
            return nil
        }
        let parent = (descriptor: parentDescriptor, url: parentURL)
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

    private enum ParentLookup {
        case opened(descriptor: Int32, url: URL)
        case missing
        /// Another user's private folder (EACCES/EPERM): skipped, not a reason to stop.
        case unreadable(String)
        /// A link or non-folder in the path (ELOOP/ENOTDIR): never followed, the real files sit under `private/`.
        case notFollowed(String)
    }

    /// A link in any parent component is never followed: it is noted and skipped.
    private static func openArtifactParent(components: [Substring], under root: URL) throws -> ParentLookup {
        var descriptor = try openCollectionRoot(root)
        var candidate = root
        for component in components.dropLast() {
            let name = String(component)
            let next = openat(descriptor, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
            guard next >= 0 else {
                let failure = errno
                _ = close(descriptor)
                let path = candidate.appendingPathComponent(name).path
                switch failure {
                case ENOENT: return .missing
                case EACCES, EPERM: return .unreadable(path)
                case ELOOP, ENOTDIR: return .notFollowed(path)
                default: throw RootstockBlueError.io("collection source contains an unsafe path component: \(path)")
                }
            }
            _ = close(descriptor)
            descriptor = next
            candidate.appendPathComponent(name, isDirectory: true)
        }
        return .opened(descriptor: descriptor, url: candidate)
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
        let fileDescriptor = openat(parent.descriptor, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW)
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
