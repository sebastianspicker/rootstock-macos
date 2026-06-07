import Foundation

public struct ShellResult: Sendable {
    public let stdout: String
    public let stderr: String
    public let terminationStatus: Int32
    public let timedOut: Bool
}

/// Shared helper for running subprocesses. Used by data sources that invoke
/// system commands (dscl, launchctl, codesign, profiles, etc.).
public enum Shell {
    /// Run a command and return stdout as a trimmed String, or nil on failure / non-zero exit.
    public static func run(_ path: String, _ arguments: [String]) -> String? {
        run(path, arguments, timeoutSeconds: nil)
    }

    /// Run a command with an optional timeout and return stdout as a trimmed String.
    public static func run(_ path: String, _ arguments: [String], timeoutSeconds: TimeInterval?) -> String? {
        guard let result = runProcess(path, arguments, timeoutSeconds: timeoutSeconds),
              result.terminationStatus == 0,
              !result.timedOut else {
            return nil
        }
        return result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Run a command, draining stdout and stderr concurrently to avoid pipe deadlocks.
    public static func runProcess(
        _ path: String,
        _ arguments: [String],
        timeoutSeconds: TimeInterval? = nil
    ) -> ShellResult? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        let outputGroup = DispatchGroup()
        let outputQueue = DispatchQueue(label: "rootstock.shell.output", attributes: .concurrent)
        var stdoutData = Data()
        var stderrData = Data()

        outputGroup.enter()
        outputQueue.async {
            stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
            outputGroup.leave()
        }

        outputGroup.enter()
        outputQueue.async {
            stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
            outputGroup.leave()
        }

        let completed = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in completed.signal() }

        do {
            try process.run()
        } catch {
            return nil
        }

        let timedOut = waitForCompletion(
            of: process,
            completionSignal: completed,
            timeoutSeconds: timeoutSeconds
        )
        outputGroup.wait()

        return ShellResult(
            stdout: String(data: stdoutData, encoding: .utf8) ?? "",
            stderr: String(data: stderrData, encoding: .utf8) ?? "",
            terminationStatus: process.terminationStatus,
            timedOut: timedOut
        )
    }

    private static func waitForCompletion(
        of process: Process,
        completionSignal: DispatchSemaphore,
        timeoutSeconds: TimeInterval?
    ) -> Bool {
        guard let timeoutSeconds else {
            process.waitUntilExit()
            return false
        }

        let deadline = DispatchTime.now() + timeoutSeconds
        if completionSignal.wait(timeout: deadline) == .timedOut {
            process.terminate()
            process.waitUntilExit()
            return true
        }
        process.waitUntilExit()
        return false
    }

    /// Run a command and return stderr as a trimmed String, or nil on failure / non-zero exit.
    /// Useful for tools like `codesign -d` that write informational output to stderr.
    public static func runStderr(_ path: String, _ arguments: [String]) -> String? {
        guard let result = runProcess(path, arguments),
              result.terminationStatus == 0,
              !result.timedOut else {
            return nil
        }
        return result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
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
