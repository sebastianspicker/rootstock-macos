import Darwin
import Foundation
import RootstockBlueCase
import RootstockBlueCore

/// Writes exports beside, never into, a verified case package. The final link
/// operation is atomic and refuses an existing destination, so an export cannot
/// silently replace operator output or case evidence.
public enum CaseOutputWriter {
    /// Generic no-clobber writer for exports that are not associated with a case.
    public static func write(_ data: Data, to destination: URL) throws {
        try publish(data, to: destination, outside: nil)
    }

    public static func write(_ data: Data, from package: CasePackage, to destination: URL) throws {
        try package.verifyIntegrity()
        try publish(data, to: destination, outside: package)
    }

    private static func publish(_ data: Data, to destination: URL, outside package: CasePackage?) throws {
        try validate(destination, isOutside: package)

        let parent = destination.deletingLastPathComponent().standardizedFileURL
        let stage = parent.appendingPathComponent(
            ".\(destination.lastPathComponent).rootstock-stage-\(UUID().uuidString)"
        )
        let descriptor = open(stage.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, S_IRUSR | S_IWUSR)
        guard descriptor >= 0 else {
            throw RootstockBlueError.io("cannot create staged export output")
        }
        do {
            let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
            try handle.write(contentsOf: data)
            try handle.synchronize()
            try handle.close()
        } catch {
            try? FileManager.default.removeItem(at: stage)
            throw error
        }
        defer { try? FileManager.default.removeItem(at: stage) }

        // Re-check immediately before the no-clobber publish step. This narrows
        // the window in which a parent could be replaced after staging.
        try validate(destination, isOutside: package)
        guard link(stage.path, destination.path) == 0 else {
            if errno == EEXIST {
                throw RootstockBlueError.io("refusing to overwrite existing export output: \(destination.path)")
            }
            throw RootstockBlueError.io("cannot publish staged export output")
        }
    }

    private static func validate(_ destination: URL, isOutside package: CasePackage?) throws {
        let target = destination.standardizedFileURL
        let parent = target.deletingLastPathComponent()
        guard try nodeType(at: parent) == .directory else {
            throw RootstockBlueError.io("export output parent must be a real directory")
        }
        if let package = package {
            // Canonicalize both sides with realpath: URL.resolvingSymlinksInPath()
            // maps existing /private paths to /tmp or /var but leaves a
            // not-yet-existing target untouched, so the two forms never compare.
            let resolvedTarget = try canonicalPath(of: parent) + "/" + target.lastPathComponent
            let caseRoot = try canonicalPath(of: package.rootURL)
            guard !isAtOrBelow(resolvedTarget, caseRoot) else {
                throw RootstockBlueError.io("export output must be outside the input case package")
            }
        }

        if let existing = try nodeTypeIfPresent(at: target) {
            let detail = existing == .symbolicLink ? "symbolic link" : "existing path"
            throw RootstockBlueError.io("refusing to overwrite \(detail): \(target.path)")
        }
    }

    private static func isAtOrBelow(_ candidate: String, _ root: String) -> Bool {
        candidate == root || candidate.hasPrefix(root + "/")
    }

    private static func canonicalPath(of url: URL) throws -> String {
        guard let resolved = realpath(url.path, nil) else {
            throw RootstockBlueError.io("cannot resolve export path: \(url.path)")
        }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    private enum OutputNodeType {
        case regularFile
        case directory
        case symbolicLink
        case other
    }

    private static func nodeType(at url: URL) throws -> OutputNodeType {
        guard let type = try nodeTypeIfPresent(at: url) else {
            throw RootstockBlueError.io("export output parent does not exist")
        }
        return type
    }

    private static func nodeTypeIfPresent(at url: URL) throws -> OutputNodeType? {
        var info = stat()
        guard lstat(url.path, &info) == 0 else {
            if errno == ENOENT { return nil }
            throw RootstockBlueError.io("cannot inspect export output path")
        }
        switch info.st_mode & S_IFMT {
        case S_IFREG: return .regularFile
        case S_IFDIR: return .directory
        case S_IFLNK: return .symbolicLink
        default: return .other
        }
    }
}
