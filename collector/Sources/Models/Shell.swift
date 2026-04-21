import Foundation

/// Shared helper for running subprocesses. Used by data sources that invoke
/// system commands (dscl, launchctl, codesign, profiles, etc.).
public enum Shell {
    /// Run a command and return stdout as a trimmed String, or nil on failure / non-zero exit.
    public static func run(_ path: String, _ arguments: [String]) -> String? {
        run(path, arguments, timeoutSeconds: nil)
    }

    /// Run a command with an optional timeout and return stdout as a trimmed String.
    public static func run(_ path: String, _ arguments: [String], timeoutSeconds: TimeInterval?) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
        } catch {
            return nil
        }

        if let timeoutSeconds {
            let completed = DispatchSemaphore(value: 0)
            process.terminationHandler = { _ in completed.signal() }
            let deadline = DispatchTime.now() + timeoutSeconds
            if completed.wait(timeout: deadline) == .timedOut {
                process.terminate()
                process.waitUntilExit()
                return nil
            }
        }

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        if timeoutSeconds == nil {
            process.waitUntilExit()
        }
        guard process.terminationStatus == 0 else { return nil }
        return String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Run a command and return stderr as a trimmed String, or nil on failure / non-zero exit.
    /// Useful for tools like `codesign -d` that write informational output to stderr.
    public static func runStderr(_ path: String, _ arguments: [String]) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments

        let pipe = Pipe()
        process.standardOutput = FileHandle.nullDevice
        process.standardError = pipe

        do {
            try process.run()
        } catch {
            return nil
        }

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { return nil }
        return String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Parse Data as a plist dictionary. Returns nil if parsing fails.
    public static func parsePlistDict(from data: Data) -> [String: Any]? {
        var format = PropertyListSerialization.PropertyListFormat.xml
        return try? PropertyListSerialization.propertyList(
            from: data, options: [], format: &format
        ) as? [String: Any]
    }

    /// Returns true if the command exits with status 0 (stdout/stderr discarded).
    public static func succeeds(_ path: String, _ arguments: [String]) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()
            return process.terminationStatus == 0
        } catch {
            return false
        }
    }
}
