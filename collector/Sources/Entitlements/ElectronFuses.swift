import Darwin
import Foundation

/// Reads the Electron fuse wire from an app's Electron Framework binary.
///
/// Electron embeds a fuse block in the framework binary: a fixed sentinel string,
/// one version byte, one count byte, then one ASCII byte per fuse ("0" disabled,
/// "1" enabled, "r" removed). Fuse wire version 1 lists `RunAsNode` first. When
/// that fuse is disabled, `ELECTRON_RUN_AS_NODE` is ignored and the environment
/// variable injection vector does not exist for the app.
///
/// See https://www.electronjs.org/docs/latest/tutorial/fuses.
enum ElectronFuses {
    static let sentinel = Data("dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX".utf8)
    static let supportedWireVersion: UInt8 = 1
    static let runAsNodeIndex = 0

    /// Largest framework binary that is scanned; bigger files leave the fuse unknown.
    static let maximumBinaryBytes = 512 * 1024 * 1024
    static let chunkBytes = 4 * 1024 * 1024
    /// Most bytes after the sentinel the parser can need (version, count, up to 255 fuse bytes).
    static let wireTailBytes = 2 + Int(UInt8.max)

    /// RunAsNode state for the framework under `frameworksURL`; nil when the fuse wire
    /// is absent (very old Electron) or the binary cannot be read.
    static func runAsNodeEnabled(frameworksURL: URL) -> Bool? {
        let binary = frameworksURL
            .appendingPathComponent("Electron Framework.framework")
            .appendingPathComponent("Electron Framework")
        return runAsNodeEnabled(binaryPath: binary.path)
    }

    /// Scans the regular file at `path` in bounded chunks for the fuse wire. Nonregular
    /// files, files over `limitBytes` and read errors yield nil.
    static func runAsNodeEnabled(
        binaryPath path: String,
        limitBytes: Int = maximumBinaryBytes,
        chunkBytes: Int = chunkBytes
    ) -> Bool? {
        let descriptor = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else { return nil }
        defer { _ = close(descriptor) }

        var info = stat()
        guard fstat(descriptor, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              info.st_size <= limitBytes else {
            return nil
        }
        return scan(descriptor: descriptor, limitBytes: limitBytes, chunkBytes: chunkBytes)
    }

    private static func scan(descriptor: Int32, limitBytes: Int, chunkBytes: Int) -> Bool? {
        // Keep enough of the previous chunk that a wire split across chunks is still found.
        let overlap = sentinel.count + wireTailBytes - 1
        var window = Data()
        var total = 0
        var buffer = [UInt8](repeating: 0, count: max(chunkBytes, 1))
        while true {
            let count = buffer.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress, $0.count) }
            if count < 0 {
                if errno == EINTR { continue }
                return nil
            }
            if count == 0 { return runAsNodeEnabled(in: window) }
            total += count
            guard total <= limitBytes else { return nil }
            window.append(contentsOf: buffer.prefix(count))
            if let state = runAsNodeEnabled(in: window) { return state }
            window = Data(window.suffix(overlap))
        }
    }

    /// Pure parser over a window of the binary contents.
    static func runAsNodeEnabled(in data: Data) -> Bool? {
        guard let range = data.range(of: sentinel) else { return nil }
        let header = range.upperBound
        guard data.count >= header + 2 else { return nil }
        let version = data[header]
        let count = Int(data[header + 1])
        guard version == supportedWireVersion, count > runAsNodeIndex,
              data.count >= header + 2 + count else { return nil }
        switch data[header + 2 + runAsNodeIndex] {
        case UInt8(ascii: "1"): return true
        case UInt8(ascii: "0"), UInt8(ascii: "r"): return false
        default: return nil
        }
    }
}
