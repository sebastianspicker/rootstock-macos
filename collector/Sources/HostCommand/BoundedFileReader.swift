import Darwin
import Foundation

public enum BoundedFileReadError: Error, CustomStringConvertible, Sendable {
    case cannotOpen(String)
    case notRegularFile
    case tooLarge(Int)
    case readFailed(String)

    public var description: String {
        switch self {
        case .cannotOpen(let message): "cannot open file: \(message)"
        case .notRegularFile: "path is not a regular file"
        case .tooLarge(let limit): "file exceeds \(limit)-byte limit"
        case .readFailed(let message): "file read failed: \(message)"
        }
    }
}

/// Descriptor-bound, nonblocking and size-bounded reads for host evidence.
public enum BoundedFileReader {
    public static let defaultLimit = 1 * 1024 * 1024

    public static func read(path: String, limit: Int = defaultLimit) throws -> Data {
        let descriptor = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else {
            throw BoundedFileReadError.cannotOpen(String(cString: strerror(errno)))
        }
        defer { _ = close(descriptor) }

        var info = stat()
        guard fstat(descriptor, &info) == 0 else {
            throw BoundedFileReadError.readFailed(String(cString: strerror(errno)))
        }
        guard (info.st_mode & S_IFMT) == S_IFREG else {
            throw BoundedFileReadError.notRegularFile
        }
        guard info.st_size <= limit else {
            throw BoundedFileReadError.tooLarge(limit)
        }

        var data = Data()
        var buffer = [UInt8](repeating: 0, count: min(64 * 1024, limit + 1))
        while data.count <= limit {
            let readLimit = min(buffer.count, limit + 1 - data.count)
            let count = buffer.withUnsafeMutableBytes {
                Darwin.read(descriptor, $0.baseAddress, readLimit)
            }
            if count > 0 {
                data.append(contentsOf: buffer.prefix(Int(count)))
            } else if count == 0 {
                return data
            } else if errno == EINTR {
                continue
            } else {
                throw BoundedFileReadError.readFailed(String(cString: strerror(errno)))
            }
        }
        throw BoundedFileReadError.tooLarge(limit)
    }
}
