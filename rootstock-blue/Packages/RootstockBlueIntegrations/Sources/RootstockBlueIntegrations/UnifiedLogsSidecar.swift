import Foundation
import RootstockBlueCore

/// Mandiant macos-UnifiedLogs sidecar wrapper - never rewrite the Rust parser in-process.
public enum UnifiedLogsSidecar {
    public static var binaryEnvironmentKey: String { "ROOTSTOCK_BLUE_ULS_BINARY" }

    public enum Status: Sendable, Equatable {
        case notConfigured
        case binaryMissing(path: String)
        case ready(path: String)
    }

    public static func resolveBinary() -> URL? {
        if let path = ProcessInfo.processInfo.environment[binaryEnvironmentKey], !path.isEmpty {
            let url = URL(fileURLWithPath: path)
            if FileManager.default.isExecutableFile(atPath: url.path) {
                return url
            }
            return url // may still exist as non-executable; status will report
        }
        return nil
    }

    public static func status() -> Status {
        guard let path = ProcessInfo.processInfo.environment[binaryEnvironmentKey], !path.isEmpty else {
            return .notConfigured
        }
        if FileManager.default.fileExists(atPath: path) {
            return .ready(path: path)
        }
        return .binaryMissing(path: path)
    }

    public static func statusMessage() -> String {
        switch status() {
        case .notConfigured:
            return "ULS sidecar not configured (set \(binaryEnvironmentKey) to Mandiant macos-unifiedlogs binary)"
        case .binaryMissing(let path):
            return "ULS sidecar binary missing at \(path)"
        case .ready(let path):
            return "ULS sidecar ready at \(path)"
        }
    }

    /// Run external sidecar if configured. Does not claim success when binary is absent.
    public static func parse(logarchive: URL, outputJSONL: URL) throws {
        guard let bin = resolveBinary() else {
            throw RootstockBlueError.notImplemented(statusMessage())
        }
        guard FileManager.default.fileExists(atPath: bin.path) else {
            throw RootstockBlueError.io("ULS binary not found: \(bin.path)")
        }
        guard FileManager.default.fileExists(atPath: logarchive.path) else {
            throw RootstockBlueError.io("logarchive not found: \(logarchive.path)")
        }

        try FileManager.default.createDirectory(
            at: outputJSONL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )

        let proc = Process()
        proc.executableURL = bin
        // Flexible argv: common Mandiant-style tools accept input path; users can wrap a shell script.
        proc.arguments = [logarchive.path, "--output", outputJSONL.path]
        let err = Pipe()
        let out = Pipe()
        proc.standardError = err
        proc.standardOutput = out
        try proc.run()
        proc.waitUntilExit()

        if proc.terminationStatus != 0 {
            let stderr = String(data: err.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            let stdout = String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            // If tool wrote output despite non-zero, still surface error honestly.
            throw RootstockBlueError.io(
                "ULS sidecar exited \(proc.terminationStatus). stderr=\(stderr.prefix(500)) stdout=\(stdout.prefix(200))"
            )
        }
    }
}
