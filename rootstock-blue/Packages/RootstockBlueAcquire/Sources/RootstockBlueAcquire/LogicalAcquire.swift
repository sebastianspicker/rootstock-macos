import Foundation
import RootstockBlueCore
import RootstockBlueCase

/// Acquisition plan describing logical collect steps and explicit non-goals.
public struct AcquisitionPlan: Sendable, Equatable {
    public var destination: URL
    public var steps: [String]
    public var nonGoals: [String]
    public var notes: [String]

    public init(destination: URL, steps: [String], nonGoals: [String], notes: [String] = []) {
        self.destination = destination
        self.steps = steps
        self.nonGoals = nonGoals
        self.notes = notes
    }
}

/// Result of materializing a fixture/evidence tree into a destination package.
public struct AcquisitionMaterializeResult: Sendable {
    public var destination: URL
    public var filesCopied: Int
    public var custodyHashes: [String: String]
    public var manifestURL: URL?

    public init(destination: URL, filesCopied: Int, custodyHashes: [String: String], manifestURL: URL? = nil) {
        self.destination = destination
        self.filesCopied = filesCopied
        self.custodyHashes = custodyHashes
        self.manifestURL = manifestURL
    }
}

/// Logical live and offline acquisition for defensive evidence-tree packages.
public enum LogicalAcquire {
    /// Build an acquisition plan for a destination evidence package root.
    public static func plan(destination: URL) -> AcquisitionPlan {
        let preflight = AcquisitionPreflight.report()
        return AcquisitionPlan(
            destination: destination,
            steps: [
                "1. Record acquisition prerequisites and unavailable capabilities",
                "2. Materialize rooted evidence tree (fixture or mounted volume with credentials)",
                "3. Write per-file SHA-256 custody hashes into evidence package",
                "4. Optionally create .rsbcase and parse with ForensicsEngine",
                "5. Run IR posture + persistence inventory + detections against case",
            ],
            nonGoals: preflight.nonGoals + [
                "Bit-for-bit APFS container image without commercial imager",
                "Unlock FileVault without credentials",
            ],
            notes: preflight.capabilities.map { "\($0.available ? "CAN" : "CANNOT"): \($0.name) - \($0.detail)" }
        )
    }

    /// Materialize a rooted source tree into a case-friendly evidence package with custody hashes.
    /// This is not FileVault unlock - it only copies already-accessible files.
    public static func materializeFixtureBundle(
        from sourceTree: URL,
        to destination: URL,
        actor: String = NSUserName()
    ) throws -> AcquisitionMaterializeResult {
        let fileManager = FileManager.default
        let source = sourceTree.standardizedFileURL
        try validateMaterialization(source: source, destination: destination, sourceTree: sourceTree, fileManager: fileManager)
        let staging = stagingDirectory(for: destination)
        do {
            try prepareStaging(staging, fileManager: fileManager)
            let copied = try copyEvidence(from: source, into: staging, fileManager: fileManager)
            let manifest = try writeBundleMetadata(staging: staging, sourceTree: sourceTree, actor: actor, copied: copied)
            try publishStaging(staging, to: destination, fileManager: fileManager)
            return AcquisitionMaterializeResult(destination: destination, filesCopied: copied.files, custodyHashes: copied.hashes, manifestURL: destination.appendingPathComponent(manifest.lastPathComponent))
        } catch {
            try? fileManager.removeItem(at: staging)
            throw error
        }
    }

    private static func validateMaterialization(source: URL, destination: URL, sourceTree: URL, fileManager: FileManager) throws {
        let resolvedSource = source.resolvingSymlinksInPath()
        let resolvedDestination = destination.standardizedFileURL.resolvingSymlinksInPath()
        guard pathEntryExistsOrIsSymlink(source, fileManager: fileManager) else { throw RootstockBlueError.io("Source tree not found: \(sourceTree.path)") }
        guard !isSymbolicLink(source, fileManager: fileManager), isDirectory(source, fileManager: fileManager) else { throw RootstockBlueError.io("Source tree must be a real directory, not a symbolic link or file: \(sourceTree.path)") }
        guard !pathsOverlap(resolvedSource, resolvedDestination) else { throw RootstockBlueError.io("Source and destination must not overlap: \(sourceTree.path) and \(destination.path)") }
        guard !pathEntryExistsOrIsSymlink(destination, fileManager: fileManager) else { throw RootstockBlueError.io("Destination already exists and will not be modified: \(destination.path)") }
        try validateSourceTree(source, fileManager: fileManager)
    }

    private static func prepareStaging(_ staging: URL, fileManager: FileManager) throws {
        try fileManager.createDirectory(at: staging.deletingLastPathComponent(), withIntermediateDirectories: true)
        try fileManager.createDirectory(at: staging, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try fileManager.createDirectory(at: staging.appendingPathComponent("evidence", isDirectory: true), withIntermediateDirectories: true)
    }

    private static func copyEvidence(from source: URL, into staging: URL, fileManager: FileManager) throws -> (files: Int, hashes: [String: String]) {
        guard let enumerator = fileManager.enumerator(at: source, includingPropertiesForKeys: [.isSymbolicLinkKey, .isRegularFileKey, .isDirectoryKey], options: []) else { throw RootstockBlueError.io("Unable to enumerate source tree: \(source.path)") }
        var copyState = EvidenceCopyState(fileManager: fileManager)
        let evidence = staging.appendingPathComponent("evidence", isDirectory: true)
        while let item = enumerator.nextObject() as? URL {
            let relative = relativePath(of: item, under: source)
            let destination = evidence.appendingPathComponent(relative)
            if try classify(item, fileManager: fileManager) == .directory {
                try fileManager.createDirectory(at: destination, withIntermediateDirectories: true)
            } else {
                try copyState.copyFile(item, relative: relative, to: destination)
            }
        }
        return (copyState.files, copyState.hashes)
    }

    private static func writeBundleMetadata(staging: URL, sourceTree: URL, actor: String, copied: (files: Int, hashes: [String: String])) throws -> URL {
        try writeHashManifest(staging: staging, hashes: copied.hashes)
        let manifestURL = staging.appendingPathComponent("acquisition_manifest.json")
        let manifest: [String: Any] = ["type": "rootstock-blue-evidence-bundle", "version": 1, "actor": actor, "source": sourceTree.path, "files_copied": copied.files, "created_at": ISO8601DateFormatter().string(from: Date()), "note": "Logical tree copy only - not FileVault unlock or bit-for-bit disk image", "non_goals": AcquisitionPreflight.report().nonGoals]
        try JSONSerialization.data(withJSONObject: manifest, options: [.prettyPrinted, .sortedKeys]).write(to: manifestURL)
        try CustodyLog.append(url: staging.appendingPathComponent("custody.jsonl"), event: CustodyEvent(actor: actor, action: "materialize_fixture_bundle", detail: "files=\(copied.files) source=\(sourceTree.path)"))
        return manifestURL
    }

    private static func writeHashManifest(staging: URL, hashes: [String: String]) throws {
        let contents = hashes.keys.sorted().map { "\(hashes[$0] ?? "")  \($0)" }.joined(separator: "\n") + "\n"
        try contents.write(to: staging.appendingPathComponent("sha256sums.txt"), atomically: true, encoding: .utf8)
    }

    private static func publishStaging(_ staging: URL, to destination: URL, fileManager: FileManager) throws {
        guard !pathEntryExistsOrIsSymlink(destination, fileManager: fileManager) else { throw RootstockBlueError.io("Destination already exists and will not be modified: \(destination.path)") }
        try fileManager.moveItem(at: staging, to: destination)
    }

    /// Legacy entry - requires destination; does not implement FV unlock.
    public static func acquire(to destination: URL, actor: String = NSUserName()) throws -> URL {
        _ = actor
        throw RootstockBlueError.notImplemented(
            "Logical acquire(to:) requires a source tree. Use plan(destination:) with materializeFixtureBundle(from:to:), or a dedicated disk-imaging tool. Destination: \(destination.path). FileVault unlock requires credentials."
        )
    }

    /// Explicit fail path: never crack FileVault.
    public static func unlockFileVault(volumeUUID: String, password: String?) throws {
        guard let password, !password.isEmpty else {
            throw RootstockBlueError.secretsRequired(
                "FileVault unlock for volume \(volumeUUID) requires user/org credentials; no crack path exists"
            )
        }
        // Even with a password string present, this product does not drive fdesetup unlock as an imager.
        throw RootstockBlueError.notImplemented(
            "FileVault credentialed unlock is out of scope for RootstockBlue logical acquire (volume=\(volumeUUID)); use Disk Utility / fdesetup / commercial imager with provided keys"
        )
    }

    // MARK: - Private

    private enum SourceItemKind {
        case directory
        case regularFile
    }

    private struct EvidenceCopyState {
        let fileManager: FileManager
        var files = 0
        var hashes: [String: String] = [:]

        mutating func copyFile(_ source: URL, relative: String, to destination: URL) throws {
            try fileManager.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
            guard !LogicalAcquire.pathEntryExistsOrIsSymlink(destination, fileManager: fileManager) else {
                throw RootstockBlueError.io("Source paths collide at destination: \(relative)")
            }
            try fileManager.copyItem(at: source, to: destination)
            files += 1
            hashes["evidence/\(relative)"] = try Hashing.sha256File(at: destination)
        }
    }

    private static func validateSourceTree(_ source: URL, fileManager: FileManager) throws {
        guard let enumerator = fileManager.enumerator(
            at: source,
            includingPropertiesForKeys: [.isSymbolicLinkKey, .isRegularFileKey, .isDirectoryKey],
            options: []
        ) else {
            throw RootstockBlueError.io("Unable to enumerate source tree: \(source.path)")
        }

        while let item = enumerator.nextObject() as? URL {
            _ = try classify(item, fileManager: fileManager)
        }
    }

    private static func classify(_ item: URL, fileManager: FileManager) throws -> SourceItemKind {
        guard pathEntryExistsOrIsSymlink(item, fileManager: fileManager) else {
            throw RootstockBlueError.io("Source item disappeared during acquisition preflight: \(item.path)")
        }
        if isSymbolicLink(item, fileManager: fileManager) {
            throw RootstockBlueError.io("Source tree contains a symbolic link, which is not acquired: \(item.path)")
        }
        if isDirectory(item, fileManager: fileManager) {
            return .directory
        }
        if isRegularFile(item, fileManager: fileManager) {
            return .regularFile
        }
        throw RootstockBlueError.io("Source tree contains a non-regular item, which is not acquired: \(item.path)")
    }

    private static func stagingDirectory(for destination: URL) -> URL {
        destination.deletingLastPathComponent().appendingPathComponent(
            ".\(destination.lastPathComponent).rootstock-staging-\(UUID().uuidString)",
            isDirectory: true
        )
    }

    private static func pathEntryExistsOrIsSymlink(_ url: URL, fileManager: FileManager) -> Bool {
        fileManager.fileExists(atPath: url.path)
            || (try? fileManager.destinationOfSymbolicLink(atPath: url.path)) != nil
    }

    private static func isSymbolicLink(_ url: URL, fileManager: FileManager) -> Bool {
        (try? fileManager.destinationOfSymbolicLink(atPath: url.path)) != nil
    }

    private static func isDirectory(_ url: URL, fileManager: FileManager) -> Bool {
        var isDirectory: ObjCBool = false
        return fileManager.fileExists(atPath: url.path, isDirectory: &isDirectory) && isDirectory.boolValue
    }

    private static func isRegularFile(_ url: URL, fileManager: FileManager) -> Bool {
        guard let attributes = try? fileManager.attributesOfItem(atPath: url.path),
              let type = attributes[.type] as? FileAttributeType else {
            return false
        }
        return type == .typeRegular
    }

    private static func pathsOverlap(_ first: URL, _ second: URL) -> Bool {
        isEqualOrDescendant(first, of: second) || isEqualOrDescendant(second, of: first)
    }

    private static func isEqualOrDescendant(_ candidate: URL, of parent: URL) -> Bool {
        let candidatePath = candidate.path
        let parentPath = parent.path
        return candidatePath == parentPath || candidatePath.hasPrefix(parentPath + "/")
    }

    private static func relativePath(of url: URL, under root: URL) -> String {
        let rootPath = root.standardizedFileURL.path
        let itemPath = url.standardizedFileURL.path
        if itemPath.hasPrefix(rootPath) {
            var rel = String(itemPath.dropFirst(rootPath.count))
            if rel.hasPrefix("/") { rel = String(rel.dropFirst()) }
            return rel.isEmpty ? url.lastPathComponent : rel
        }
        return url.lastPathComponent
    }
}
