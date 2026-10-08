import CryptoKit
import Darwin
import Foundation

/// Size-bounded SHA-256 digests of host files (same descriptor rules as `BoundedFileReader`).
public enum FileDigest {
    public static let defaultLimit = 64 * 1024 * 1024

    /// Lower-case hex SHA-256 of the regular file at `path`, or nil when the file cannot be
    /// opened, is not a regular file, or is larger than `limitBytes`.
    public static func sha256(ofFileAt path: String, limitBytes: Int = defaultLimit) -> String? {
        let descriptor = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else { return nil }
        defer { _ = close(descriptor) }

        var info = stat()
        guard fstat(descriptor, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              info.st_size <= limitBytes else {
            return nil
        }

        var hasher = SHA256()
        var total = 0
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = buffer.withUnsafeMutableBytes {
                Darwin.read(descriptor, $0.baseAddress, $0.count)
            }
            if count > 0 {
                total += count
                guard total <= limitBytes else { return nil }
                buffer.withUnsafeBytes { hasher.update(bufferPointer: UnsafeRawBufferPointer(rebasing: $0.prefix(count))) }
            } else if count == 0 {
                break
            } else if errno != EINTR {
                return nil
            }
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}

/// File modification times in the collector's ISO 8601 UTC format.
public enum FileTimestamp {
    /// ISO 8601 UTC modification time of `path` (e.g. `2026-10-08T06:34:44Z`), or nil when unreadable.
    public static func modified(path: String) -> String? {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: path),
              let date = attributes[.modificationDate] as? Date else {
            return nil
        }
        return ISO8601DateFormatter().string(from: date)
    }
}
