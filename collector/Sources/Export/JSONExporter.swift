import Foundation
import Models
import Darwin

public enum JSONExporterError: LocalizedError {
    case outputExists(String)
    case outputIsSymlink(String)
    case outputIsNotRegularFile(String)
    case cannotOpen(String, String)
    case writeFailed(String, String)

    public var errorDescription: String? {
        switch self {
        case .outputExists(let path):
            return "Output file already exists: \(path). Re-run with --force to replace it."
        case .outputIsSymlink(let path):
            return "Refusing to write output through a symbolic link: \(path)"
        case .outputIsNotRegularFile(let path):
            return "Refusing to replace non-regular output path: \(path)"
        case .cannotOpen(let path, let message):
            return "Cannot open output file at \(path): \(message)"
        case .writeFailed(let path, let message):
            return "Cannot write output file at \(path): \(message)"
        }
    }
}

/// Test-only failure points for exercising the no-partial-overwrite guarantee.
///
/// This is internal so it does not alter the collector's public CLI contract.
enum JSONExporterTestFailure: Sendable {
    case beforePublish
    case createDestinationBeforePublish
    case afterPublishBeforeDirectorySync
}

/// Serializes a ScanResult to JSON and writes it to disk.
public struct JSONExporter {
    private let encoder: JSONEncoder
    private let testFailure: JSONExporterTestFailure?

    public init() {
        self.init(testFailure: nil)
    }

    init(testFailure: JSONExporterTestFailure?) {
        encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        self.testFailure = testFailure
    }

    /// Encode a ScanResult to JSON data.
    public func encode(_ result: ScanResult) throws -> Data {
        return try encoder.encode(result)
    }

    /// Write a ScanResult as JSON to the given file path.
    public func write(_ result: ScanResult, to path: String, force: Bool = false) throws {
        let data = try encode(result)
        try writeSecurely(data, to: path, force: force)
    }

    private func writeSecurely(_ data: Data, to path: String, force: Bool) throws {
        let directory = outputDirectory(for: path)
        let directoryFD = try openDirectory(directory, outputPath: path)
        defer { close(directoryFD) }

        let filename = try outputFilename(for: path)
        try validateOutputPath(
            path,
            filename: filename,
            directoryFD: directoryFD,
            force: force
        )

        let stagingName = ".\(filename).\(UUID().uuidString).tmpdir"
        guard mkdirat(directoryFD, stagingName, mode_t(S_IRWXU)) == 0 else {
            throw JSONExporterError.cannotOpen(path, String(cString: strerror(errno)))
        }
        defer { _ = unlinkat(directoryFD, stagingName, AT_REMOVEDIR) }
        let stagingFD = openat(directoryFD, stagingName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard stagingFD >= 0 else {
            throw JSONExporterError.cannotOpen(path, String(cString: strerror(errno)))
        }
        defer { _ = close(stagingFD) }
        try enforceOwnerOnlyPermissions(stagingFD, mode: mode_t(S_IRWXU), path: path)

        let temporaryName = "payload"
        var shouldRemoveTemporaryFile = true
        defer {
            if shouldRemoveTemporaryFile {
                _ = unlinkat(stagingFD, temporaryName, 0)
            }
        }

        let temporaryFD = try openTemporaryFile(
            temporaryName,
            directoryFD: stagingFD,
            outputPath: path
        )
        do {
            try enforceOwnerOnlyPermissions(
                temporaryFD,
                mode: mode_t(S_IRUSR | S_IWUSR),
                path: path
            )
            try writeAll(data, to: temporaryFD, path: path)
            try finishTemporaryFile(temporaryFD, path: path)
        } catch {
            _ = close(temporaryFD)
            throw error
        }
        guard close(temporaryFD) == 0 else {
            throw JSONExporterError.writeFailed(path, String(cString: strerror(errno)))
        }

        if testFailure == .beforePublish {
            throw JSONExporterError.writeFailed(path, "test-injected failure before atomic publish")
        }
        if testFailure == .createDestinationBeforePublish {
            try createRacingDestination(
                filename,
                directoryFD: directoryFD,
                outputPath: path
            )
        }

        try publishTemporaryFile(
            temporaryName,
            as: filename,
            sourceDirectoryFD: stagingFD,
            destinationDirectoryFD: directoryFD,
            outputPath: path,
            force: force
        )
        shouldRemoveTemporaryFile = false

        if testFailure == .afterPublishBeforeDirectorySync {
            throw JSONExporterError.writeFailed(
                path,
                "output was published but directory durability is unknown (test-injected)"
            )
        }

        try synchronizeDirectory(directoryFD, outputPath: path)
    }

    private func outputDirectory(for path: String) -> String {
        let directory = (path as NSString).deletingLastPathComponent
        return directory.isEmpty ? "." : directory
    }

    private func outputFilename(for path: String) throws -> String {
        let filename = (path as NSString).lastPathComponent
        guard !filename.isEmpty else {
            throw JSONExporterError.cannotOpen(path, "output path has no filename")
        }
        return filename
    }

    private func validateOutputPath(
        _ path: String,
        filename: String,
        directoryFD: Int32,
        force: Bool
    ) throws {
        var statInfo = stat()
        if fstatat(directoryFD, filename, &statInfo, AT_SYMLINK_NOFOLLOW) == 0 {
            let fileType = statInfo.st_mode & S_IFMT
            if fileType == S_IFLNK {
                throw JSONExporterError.outputIsSymlink(path)
            }
            if !force {
                throw JSONExporterError.outputExists(path)
            }
            if fileType != S_IFREG {
                throw JSONExporterError.outputIsNotRegularFile(path)
            }
        } else if errno != ENOENT {
            throw JSONExporterError.cannotOpen(path, String(cString: strerror(errno)))
        }
    }

    private func openDirectory(_ directory: String, outputPath: String) throws -> Int32 {
        let fd = open(directory, O_RDONLY | O_DIRECTORY)
        guard fd >= 0 else {
            throw JSONExporterError.cannotOpen(outputPath, String(cString: strerror(errno)))
        }
        return fd
    }

    private func openTemporaryFile(
        _ temporaryName: String,
        directoryFD: Int32,
        outputPath: String
    ) throws -> Int32 {
        let fd = openat(
            directoryFD,
            temporaryName,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
            mode_t(S_IRUSR | S_IWUSR)
        )
        guard fd >= 0 else {
            if errno == ELOOP {
                throw JSONExporterError.outputIsSymlink(outputPath)
            }
            throw JSONExporterError.cannotOpen(outputPath, String(cString: strerror(errno)))
        }
        return fd
    }

    private func enforceOwnerOnlyPermissions(_ fd: Int32, mode: mode_t, path: String) throws {
        guard fchmod(fd, mode) == 0 else {
            throw JSONExporterError.writeFailed(path, String(cString: strerror(errno)))
        }
        guard let emptyACL = acl_init(0) else {
            throw JSONExporterError.writeFailed(path, String(cString: strerror(errno)))
        }
        defer { _ = acl_free(UnsafeMutableRawPointer(emptyACL)) }
        guard acl_set_fd_np(fd, emptyACL, ACL_TYPE_EXTENDED) == 0 else {
            throw JSONExporterError.writeFailed(path, String(cString: strerror(errno)))
        }
    }

    private func writeAll(_ data: Data, to fd: Int32, path: String) throws {
        try data.withUnsafeBytes { buffer in
            guard var pointer = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return
            }
            var remaining = buffer.count
            while remaining > 0 {
                let written = Darwin.write(fd, pointer, remaining)
                if written < 0 {
                    if errno == EINTR { continue }
                    throw JSONExporterError.writeFailed(path, String(cString: strerror(errno)))
                }
                remaining -= written
                pointer = pointer.advanced(by: written)
            }
        }
    }

    private func finishTemporaryFile(_ fd: Int32, path: String) throws {
        try synchronizeFile(fd, path: path)
    }

    private func publishTemporaryFile(
        _ temporaryName: String,
        as filename: String,
        sourceDirectoryFD: Int32,
        destinationDirectoryFD: Int32,
        outputPath: String,
        force: Bool
    ) throws {
        if force {
            guard renameat(
                sourceDirectoryFD,
                temporaryName,
                destinationDirectoryFD,
                filename
            ) == 0 else {
                throw JSONExporterError.writeFailed(outputPath, String(cString: strerror(errno)))
            }
            return
        }

        guard linkat(
            sourceDirectoryFD,
            temporaryName,
            destinationDirectoryFD,
            filename,
            0
        ) == 0 else {
            if errno == EEXIST {
                throw JSONExporterError.outputExists(outputPath)
            }
            throw JSONExporterError.writeFailed(outputPath, String(cString: strerror(errno)))
        }
        guard unlinkat(sourceDirectoryFD, temporaryName, 0) == 0 else {
            throw JSONExporterError.writeFailed(
                outputPath,
                "output was published but temporary cleanup failed: \(String(cString: strerror(errno)))"
            )
        }
    }

    private func createRacingDestination(
        _ filename: String,
        directoryFD: Int32,
        outputPath: String
    ) throws {
        let fd = openat(
            directoryFD,
            filename,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
            mode_t(S_IRUSR | S_IWUSR)
        )
        guard fd >= 0 else {
            throw JSONExporterError.writeFailed(outputPath, String(cString: strerror(errno)))
        }
        defer { _ = close(fd) }
        try writeAll(Data("racer".utf8), to: fd, path: outputPath)
        try synchronizeFile(fd, path: outputPath)
    }

    private func synchronizeFile(_ fd: Int32, path: String) throws {
        while fsync(fd) != 0 {
            if errno == EINTR { continue }
            throw JSONExporterError.writeFailed(path, String(cString: strerror(errno)))
        }
    }

    private func synchronizeDirectory(_ fd: Int32, outputPath: String) throws {
        while fsync(fd) != 0 {
            if errno == EINTR { continue }
            throw JSONExporterError.writeFailed(
                outputPath,
                "output was published but directory durability is unknown: \(String(cString: strerror(errno)))"
            )
        }
    }
}
