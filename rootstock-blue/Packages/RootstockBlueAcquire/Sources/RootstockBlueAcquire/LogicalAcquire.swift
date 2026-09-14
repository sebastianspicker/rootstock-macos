import CryptoKit
import Darwin
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
        try materializeFixtureBundle(
            from: sourceTree,
            to: destination,
            actor: actor,
            afterSourceValidation: nil,
            afterSourceFileOpen: nil
        )
    }

    /// Test-only deterministic race seam. It is internal to the module and is
    /// not exposed by the product library or CLI.
    static func materializeFixtureBundleForTesting(
        from sourceTree: URL,
        to destination: URL,
        actor: String = NSUserName(),
        afterSourceValidation: (() throws -> Void)? = nil,
        afterSourceFileOpen: ((String) throws -> Void)? = nil
    ) throws -> AcquisitionMaterializeResult {
        try materializeFixtureBundle(
            from: sourceTree,
            to: destination,
            actor: actor,
            afterSourceValidation: afterSourceValidation,
            afterSourceFileOpen: afterSourceFileOpen
        )
    }

    private static func materializeFixtureBundle(
        from sourceTree: URL,
        to destination: URL,
        actor: String,
        afterSourceValidation: (() throws -> Void)?,
        afterSourceFileOpen: ((String) throws -> Void)?
    ) throws -> AcquisitionMaterializeResult {
        let fileManager = FileManager.default
        let source = sourceTree.standardizedFileURL
        let sourceSnapshot = try validateMaterialization(source: source, destination: destination, sourceTree: sourceTree, fileManager: fileManager)
        try afterSourceValidation?()
        let staging = stagingDirectory(for: destination)
        do {
            try prepareStaging(staging, fileManager: fileManager)
            let copied = try copyEvidence(
                from: source,
                expectedSnapshot: sourceSnapshot,
                into: staging,
                afterSourceFileOpen: afterSourceFileOpen
            )
            let manifest = try writeBundleMetadata(staging: staging, sourceTree: sourceTree, actor: actor, copied: copied)
            try publishStaging(staging, to: destination, fileManager: fileManager)
            return AcquisitionMaterializeResult(destination: destination, filesCopied: copied.files, custodyHashes: copied.hashes, manifestURL: destination.appendingPathComponent(manifest.lastPathComponent))
        } catch {
            try? fileManager.removeItem(at: staging)
            throw error
        }
    }

    private static func validateMaterialization(source: URL, destination: URL, sourceTree: URL, fileManager: FileManager) throws -> FileSnapshot {
        let resolvedSource = source.resolvingSymlinksInPath()
        let resolvedDestination = destination.standardizedFileURL.resolvingSymlinksInPath()
        guard pathEntryExistsOrIsSymlink(source, fileManager: fileManager) else { throw RootstockBlueError.io("Source tree not found: \(sourceTree.path)") }
        guard !isSymbolicLink(source, fileManager: fileManager), isDirectory(source, fileManager: fileManager) else { throw RootstockBlueError.io("Source tree must be a real directory, not a symbolic link or file: \(sourceTree.path)") }
        guard source.path == resolvedSource.path else { throw RootstockBlueError.io("Source tree must not traverse a symbolic link: \(sourceTree.path)") }
        guard !pathsOverlap(resolvedSource, resolvedDestination) else { throw RootstockBlueError.io("Source and destination must not overlap: \(sourceTree.path) and \(destination.path)") }
        guard !pathEntryExistsOrIsSymlink(destination, fileManager: fileManager) else { throw RootstockBlueError.io("Destination already exists and will not be modified: \(destination.path)") }
        return try openDirectoryNoFollow(at: source) { descriptor in
            try fileSnapshot(of: descriptor, label: "source tree")
        }
    }

    private static func prepareStaging(_ staging: URL, fileManager: FileManager) throws {
        try fileManager.createDirectory(at: staging.deletingLastPathComponent(), withIntermediateDirectories: true)
        try fileManager.createDirectory(at: staging, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try fileManager.createDirectory(at: staging.appendingPathComponent("evidence", isDirectory: true), withIntermediateDirectories: true)
    }

    private static func copyEvidence(
        from source: URL,
        expectedSnapshot: FileSnapshot,
        into staging: URL,
        afterSourceFileOpen: ((String) throws -> Void)?
    ) throws -> (files: Int, hashes: [String: String]) {
        var copyState = EvidenceCopyState()
        let evidence = staging.appendingPathComponent("evidence", isDirectory: true)
        try openDirectoryNoFollow(at: source) { descriptor in
            guard try fileSnapshot(of: descriptor, label: "source tree") == expectedSnapshot else {
                throw RootstockBlueError.io("Source tree changed before acquisition")
            }
            try copyDirectoryContents(
                directoryFD: descriptor,
                expectedSnapshot: expectedSnapshot,
                relativeComponents: [],
                destinationDirectory: evidence,
                copyState: &copyState,
                afterSourceFileOpen: afterSourceFileOpen
            )
        }
        try requirePathSnapshot(source, expected: expectedSnapshot, label: "source tree")
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

    private struct FileIdentity: Equatable {
        let device: dev_t
        let inode: ino_t
    }

    /// A descriptor snapshot catches ordinary in-place changes as well as path
    /// replacement. The same descriptor is used for bytes and SHA-256, so the
    /// manifest always describes the copied bytes even if a hostile writer
    /// races us; a detected mutation fails the acquisition before publish.
    private struct FileSnapshot: Equatable {
        let identity: FileIdentity
        let size: off_t
        let modificationSeconds: Int
        let modificationNanoseconds: Int
    }

    private struct EvidenceCopyState {
        var files = 0
        var hashes: [String: String] = [:]

        mutating func record(relativeComponents: [String], hash: String) {
            files += 1
            hashes["evidence/\(relativeComponents.joined(separator: "/"))"] = hash
        }
    }

    private static func copyDirectoryContents(
        directoryFD: Int32,
        expectedSnapshot: FileSnapshot,
        relativeComponents: [String],
        destinationDirectory: URL,
        copyState: inout EvidenceCopyState,
        afterSourceFileOpen: ((String) throws -> Void)?
    ) throws {
        guard try fileSnapshot(of: directoryFD, label: "source directory") == expectedSnapshot else {
            throw RootstockBlueError.io("Source directory was replaced during acquisition")
        }
        let enumerationFD = dup(directoryFD)
        guard enumerationFD >= 0, let directory = fdopendir(enumerationFD) else {
            if enumerationFD >= 0 { _ = close(enumerationFD) }
            throw RootstockBlueError.io("Unable to enumerate source directory safely")
        }
        defer { closedir(directory) }

        while let entry = readdir(directory) {
            let name = directoryEntryName(entry)
            guard name != ".", name != ".." else { continue }
            var entryInfo = stat()
            guard fstatat(directoryFD, name, &entryInfo, AT_SYMLINK_NOFOLLOW) == 0 else {
                throw RootstockBlueError.io("Source entry disappeared during acquisition: \(displayPath(relativeComponents, name))")
            }
            try copyDirectoryEntry(
                parentFD: directoryFD,
                name: name,
                info: entryInfo,
                parentComponents: relativeComponents,
                destinationDirectory: destinationDirectory,
                copyState: &copyState,
                afterSourceFileOpen: afterSourceFileOpen
            )
        }
    }

    private static func copyDirectoryEntry(
        parentFD: Int32,
        name: String,
        info: stat,
        parentComponents: [String],
        destinationDirectory: URL,
        copyState: inout EvidenceCopyState,
        afterSourceFileOpen: ((String) throws -> Void)?
    ) throws {
        let relative = parentComponents + [name]
        switch info.st_mode & S_IFMT {
        case S_IFDIR:
            try copyChildDirectory(
                parentFD: parentFD, name: name, info: info, relative: relative,
                destinationDirectory: destinationDirectory, copyState: &copyState,
                afterSourceFileOpen: afterSourceFileOpen
            )
        case S_IFREG:
            try copyRegularFile(
                parentFD: parentFD, name: name, expected: fileSnapshot(of: info),
                relativeComponents: relative, destinationDirectory: destinationDirectory,
                copyState: &copyState, afterSourceFileOpen: afterSourceFileOpen
            )
        case S_IFLNK:
            throw RootstockBlueError.io("Source tree contains a symbolic link, which is not acquired: \(displayPath(parentComponents, name))")
        default:
            throw RootstockBlueError.io("Source tree contains a non-regular item, which is not acquired: \(displayPath(parentComponents, name))")
        }
    }

    private static func copyChildDirectory(
        parentFD: Int32,
        name: String,
        info: stat,
        relative: [String],
        destinationDirectory: URL,
        copyState: inout EvidenceCopyState,
        afterSourceFileOpen: ((String) throws -> Void)?
    ) throws {
        let label = relative.joined(separator: "/")
        let childFD = try openChildDirectory(parentFD: parentFD, name: name, label: label)
        defer { _ = close(childFD) }
        let childSnapshot = try validatedChildSnapshot(childFD, info: info, label: label)
        let destination = destinationDirectory.appendingPathComponent(name, isDirectory: true)
        try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try copyDirectoryContents(
            directoryFD: childFD, expectedSnapshot: childSnapshot, relativeComponents: relative,
            destinationDirectory: destination, copyState: &copyState,
            afterSourceFileOpen: afterSourceFileOpen
        )
        try requireEntrySnapshot(parentFD, name: name, expected: childSnapshot, label: label)
    }

    private static func openChildDirectory(parentFD: Int32, name: String, label: String) throws -> Int32 {
        let childFD = openat(parentFD, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard childFD >= 0 else {
            throw RootstockBlueError.io("Cannot open source directory without following links: \(label)")
        }
        return childFD
    }

    private static func validatedChildSnapshot(_ descriptor: Int32, info: stat, label: String) throws -> FileSnapshot {
        let childSnapshot = try fileSnapshot(of: descriptor, label: label)
        guard childSnapshot == fileSnapshot(of: info) else {
            throw RootstockBlueError.io("Source directory changed during acquisition: \(label)")
        }
        return childSnapshot
    }

    private static func copyRegularFile(
        parentFD: Int32,
        name: String,
        expected: FileSnapshot,
        relativeComponents: [String],
        destinationDirectory: URL,
        copyState: inout EvidenceCopyState,
        afterSourceFileOpen: ((String) throws -> Void)?
    ) throws {
        let label = relativeComponents.joined(separator: "/")
        let sourceFD = try openExpectedSourceFile(parentFD: parentFD, name: name, expected: expected, label: label)
        defer { _ = close(sourceFD) }
        try afterSourceFileOpen?(label)
        let destinationFD = try openStagedDestination(destinationDirectory.appendingPathComponent(name), label: label)
        defer { _ = close(destinationFD) }
        let digest = try copyBytes(sourceFD: sourceFD, destinationFD: destinationFD, label: label)
        try requireUnchangedSourceFile(sourceFD, parentFD: parentFD, name: name, expected: expected, label: label)
        copyState.record(relativeComponents: relativeComponents, hash: digest)
    }

    private static func openExpectedSourceFile(parentFD: Int32, name: String, expected: FileSnapshot, label: String) throws -> Int32 {
        let descriptor = openat(parentFD, name, O_RDONLY | O_NOFOLLOW)
        guard descriptor >= 0 else {
            throw RootstockBlueError.io("Cannot open source file without following links: \(label)")
        }
        do {
            guard try fileSnapshot(of: descriptor, label: label) == expected else {
                throw RootstockBlueError.io("Source file changed during acquisition: \(label)")
            }
            return descriptor
        } catch {
            _ = close(descriptor)
            throw error
        }
    }

    private static func openStagedDestination(_ url: URL, label: String) throws -> Int32 {
        let descriptor = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else {
            throw RootstockBlueError.io("Cannot safely stage source file: \(label)")
        }
        return descriptor
    }

    private static func copyBytes(sourceFD: Int32, destinationFD: Int32, label: String) throws -> String {
        var hasher = SHA256()
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while let bytes = try readChunk(sourceFD, into: &buffer, label: label) {
            try writeChunk(buffer, count: bytes, to: destinationFD, label: label)
            hasher.update(data: Data(buffer.prefix(bytes)))
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    private static func readChunk(_ descriptor: Int32, into buffer: inout [UInt8], label: String) throws -> Int? {
        while true {
            let count = read(descriptor, &buffer, buffer.count)
            if count >= 0 { return count == 0 ? nil : Int(count) }
            if errno != EINTR { throw RootstockBlueError.io("Cannot read source file: \(label)") }
        }
    }

    private static func writeChunk(_ buffer: [UInt8], count: Int, to descriptor: Int32, label: String) throws {
        var written = 0
        while written < count {
            let result = buffer.withUnsafeBytes { rawBuffer in
                write(descriptor, rawBuffer.baseAddress!.advanced(by: written), count - written)
            }
            if result >= 0 {
                written += Int(result)
            } else if errno != EINTR {
                throw RootstockBlueError.io("Cannot stage source file: \(label)")
            }
        }
    }

    private static func requireUnchangedSourceFile(
        _ descriptor: Int32, parentFD: Int32, name: String, expected: FileSnapshot, label: String
    ) throws {
        guard try fileSnapshot(of: descriptor, label: label) == expected else {
            throw RootstockBlueError.io("Source file changed during acquisition: \(label)")
        }
        try requireEntrySnapshot(parentFD, name: name, expected: expected, label: label)
    }

    private static func openDirectoryNoFollow<T>(at url: URL, _ body: (Int32) throws -> T) throws -> T {
        let components = url.standardizedFileURL.pathComponents
        guard components.first == "/" else {
            throw RootstockBlueError.io("Source tree must use an absolute path: \(url.path)")
        }
        var descriptor = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard descriptor >= 0 else { throw RootstockBlueError.io("Cannot open filesystem root") }
        for component in components.dropFirst() where !component.isEmpty && component != "." {
            let child = openat(descriptor, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
            guard child >= 0 else {
                _ = close(descriptor)
                throw RootstockBlueError.io("Cannot open source tree without following links: \(url.path)")
            }
            _ = close(descriptor)
            descriptor = child
        }
        defer { _ = close(descriptor) }
        return try body(descriptor)
    }

    private static func fileSnapshot(of descriptor: Int32, label: String) throws -> FileSnapshot {
        var info = stat()
        guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR || (info.st_mode & S_IFMT) == S_IFREG else {
            throw RootstockBlueError.io("Expected a regular source filesystem object: \(label)")
        }
        return fileSnapshot(of: info)
    }

    private static func fileSnapshot(of info: stat) -> FileSnapshot {
        FileSnapshot(
            identity: FileIdentity(device: info.st_dev, inode: info.st_ino),
            size: info.st_size,
            modificationSeconds: Int(info.st_mtimespec.tv_sec),
            modificationNanoseconds: Int(info.st_mtimespec.tv_nsec)
        )
    }

    private static func requireEntrySnapshot(_ parentFD: Int32, name: String, expected: FileSnapshot, label: String) throws {
        var info = stat()
        guard fstatat(parentFD, name, &info, AT_SYMLINK_NOFOLLOW) == 0,
              fileSnapshot(of: info) == expected else {
            throw RootstockBlueError.io("Source entry changed during acquisition: \(label)")
        }
    }

    private static func requirePathSnapshot(_ url: URL, expected: FileSnapshot, label: String) throws {
        var info = stat()
        guard lstat(url.path, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFDIR,
              fileSnapshot(of: info) == expected else {
            throw RootstockBlueError.io("Source tree changed during acquisition: \(label)")
        }
    }

    private static func directoryEntryName(_ entry: UnsafeMutablePointer<dirent>) -> String {
        withUnsafePointer(to: &entry.pointee.d_name) { names in
            names.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN)) { String(cString: $0) }
        }
    }

    private static func displayPath(_ parent: [String], _ name: String) -> String {
        (parent + [name]).joined(separator: "/")
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
