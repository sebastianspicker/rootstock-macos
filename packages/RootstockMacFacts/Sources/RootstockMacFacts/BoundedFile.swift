import Darwin
import Foundation

/// Size-bounded read of a regular file that never blocks. A FIFO, device or oversized file
/// planted in a user-writable folder must not stall or flood an assessment that runs as root.
public enum BoundedFile {
    public static func read(path: String, limit: Int) -> Data? {
        let descriptor = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else { return nil }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        var info = stat()
        guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_size <= off_t(limit)
        else { return nil }
        return (try? handle.read(upToCount: limit)) ?? Data()
    }
}
