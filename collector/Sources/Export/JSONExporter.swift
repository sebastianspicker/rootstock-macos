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

/// Serializes a ScanResult to JSON and writes it to disk.
public struct JSONExporter {
    private let encoder: JSONEncoder

    public init() {
        encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    }

    /// Encode a ScanResult to JSON data.
    public func encode(_ result: ScanResult) throws -> Data {
        return try encoder.encode(result)
    }

    /// Write a ScanResult as JSON to the given file path.
    ///
    /// After writing, the output is re-parsed as a sanity check to confirm it is valid JSON.
    public func write(_ result: ScanResult, to path: String, force: Bool = false) throws {
        let data = try encode(result)
        try writeSecurely(data, to: path, force: force)

        // Sanity check: re-parse to confirm the written file is valid JSON.
        guard (try? JSONSerialization.jsonObject(with: data, options: [])) != nil else {
            throw CocoaError(.fileWriteUnknown, userInfo: [
                NSLocalizedDescriptionKey: "Encoded JSON failed to re-parse — output may be corrupt: \(path)"
            ])
        }
    }

    private func writeSecurely(_ data: Data, to path: String, force: Bool) throws {
        var statInfo = stat()
        if lstat(path, &statInfo) == 0 {
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

        let flags = O_WRONLY | O_CREAT | O_NOFOLLOW | (force ? O_TRUNC : O_EXCL)
        let fd = open(path, flags, mode_t(S_IRUSR | S_IWUSR))
        guard fd >= 0 else {
            if errno == ELOOP {
                throw JSONExporterError.outputIsSymlink(path)
            }
            throw JSONExporterError.cannotOpen(path, String(cString: strerror(errno)))
        }
        defer { close(fd) }

        guard fchmod(fd, mode_t(S_IRUSR | S_IWUSR)) == 0 else {
            throw JSONExporterError.writeFailed(path, String(cString: strerror(errno)))
        }

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
}
