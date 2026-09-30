import Foundation
import Darwin
import os

private final class PipeCapture: Sendable {
    let pipe = Pipe()

    private let queue: DispatchQueue
    private let source: DispatchSourceRead
    private let stopped = DispatchSemaphore(value: 0)
    private let fileDescriptor: Int32
    private let data = OSAllocatedUnfairLock(initialState: Data())

    init(label: String) {
        queue = DispatchQueue(label: label)
        fileDescriptor = pipe.fileHandleForReading.fileDescriptor
        source = DispatchSource.makeReadSource(fileDescriptor: fileDescriptor, queue: queue)

        let flags = fcntl(fileDescriptor, F_GETFL)
        if flags >= 0 {
            _ = fcntl(fileDescriptor, F_SETFL, flags | O_NONBLOCK)
        }

        source.setEventHandler { [weak self] in
            guard let self else { return }
            if self.drainAvailableBytes() {
                self.source.cancel()
            }
        }
        source.setCancelHandler { [weak self] in
            guard let self else { return }
            _ = self.drainAvailableBytes()
            try? self.pipe.fileHandleForReading.close()
            self.stopped.signal()
        }
        source.resume()
    }

    func finish() -> Data {
        source.cancel()
        stopped.wait()
        return data.withLock { $0 }
    }

    /// Drain without blocking so descendant-held write descriptors cannot delay return.
    /// Returns true only after observing EOF or a terminal read error.
    private func drainAvailableBytes() -> Bool {
        var bytes = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = bytes.withUnsafeMutableBytes { buffer in
                Darwin.read(fileDescriptor, buffer.baseAddress, buffer.count)
            }
            if count > 0 {
                let chunk = Data(bytes.prefix(Int(count)))
                data.withLock { $0.append(chunk) }
            } else if count == 0 {
                return true
            } else if errno == EINTR {
                continue
            } else {
                return errno != EAGAIN && errno != EWOULDBLOCK
            }
        }
    }
}

public struct ShellResult: Sendable {
    public let stdout: String
    public let stderr: String
    public let terminationStatus: Int32
    public let timedOut: Bool

    public init(
        stdout: String,
        stderr: String,
        terminationStatus: Int32,
        timedOut: Bool
    ) {
        self.stdout = stdout
        self.stderr = stderr
        self.terminationStatus = terminationStatus
        self.timedOut = timedOut
    }
}

public enum ShellOutcome: Sendable {
    case success(ShellResult)
    case admissionTimedOut
    case launchFailed(String)
    case executionTimedOut(ShellResult)
    case nonZeroExit(ShellResult)

    public var result: ShellResult? {
        switch self {
        case .success(let result),
             .executionTimedOut(let result),
             .nonZeroExit(let result):
            return result
        case .admissionTimedOut, .launchFailed:
            return nil
        }
    }

    public var failureDescription: String? {
        switch self {
        case .success:
            return nil
        case .admissionTimedOut:
            return "admission timed out before process launch"
        case .launchFailed(let message):
            return "process launch failed: \(message)"
        case .executionTimedOut:
            return "process execution timed out"
        case .nonZeroExit(let result):
            let stderr = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            if stderr.isEmpty {
                return "process exited with status \(result.terminationStatus)"
            }
            return "process exited with status \(result.terminationStatus): \(stderr)"
        }
    }
}

public typealias ShellCommand = @Sendable (String, [String], TimeInterval?) -> ShellOutcome

public enum ShellCommandRunner {
    public static func run(
        _ path: String,
        _ arguments: [String],
        _ timeoutSeconds: TimeInterval?
    ) -> ShellOutcome {
        Shell.execute(path, arguments, timeoutSeconds: timeoutSeconds)
    }
}

/// Shared helper for running subprocesses. Used by data sources that invoke
/// system commands (dscl, launchctl, codesign, profiles, etc.).
public enum Shell {
    /// Every collector command has a finite runtime budget so a stalled system
    /// utility cannot prevent the scan from completing.
    public static let defaultTimeoutSeconds: TimeInterval = 15

    /// Waiting for a process slot is bounded independently from command execution.
    public static let defaultAdmissionTimeoutSeconds: TimeInterval = 15

    /// Limit concurrently-running collector utilities. Several data sources
    /// invoke system tools, and unbounded fan-out can exhaust file descriptors.
    static let processSlotLimit = 4
    private static let processSlots = DispatchSemaphore(value: processSlotLimit)

    /// Run a command and return stdout as a trimmed String, or nil on failure / non-zero exit.
    public static func run(_ path: String, _ arguments: [String]) -> String? {
        run(path, arguments, timeoutSeconds: defaultTimeoutSeconds)
    }

    /// Run a command with an optional timeout and return stdout as a trimmed String.
    public static func run(_ path: String, _ arguments: [String], timeoutSeconds: TimeInterval?) -> String? {
        guard case .success(let result) = execute(
            path,
            arguments,
            timeoutSeconds: timeoutSeconds
        ) else {
            return nil
        }
        return result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Run a command and preserve the reason it did not produce successful evidence.
    public static func execute(
        _ path: String,
        _ arguments: [String],
        timeoutSeconds: TimeInterval? = defaultTimeoutSeconds
    ) -> ShellOutcome {
        execute(
            path,
            arguments,
            timeoutSeconds: timeoutSeconds,
            admissionTimeoutSeconds: defaultAdmissionTimeoutSeconds
        )
    }

    static func execute(
        _ path: String,
        _ arguments: [String],
        timeoutSeconds: TimeInterval?,
        admissionTimeoutSeconds: TimeInterval
    ) -> ShellOutcome {
        let admissionDeadline = DispatchTime.now() + max(0, admissionTimeoutSeconds)
        guard processSlots.wait(timeout: admissionDeadline) == .success else {
            return .admissionTimedOut
        }
        defer { processSlots.signal() }

        let executionDeadline = timeoutSeconds.map {
            DispatchTime.now() + max(0, $0)
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments

        let stdoutCapture = PipeCapture(label: "rootstock.shell.stdout")
        let stderrCapture = PipeCapture(label: "rootstock.shell.stderr")
        process.standardOutput = stdoutCapture.pipe
        process.standardError = stderrCapture.pipe

        let completed = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in completed.signal() }

        do {
            try process.run()
        } catch {
            _ = stdoutCapture.finish()
            _ = stderrCapture.finish()
            return .launchFailed(error.localizedDescription)
        }

        let timedOut = waitForCompletion(
            of: process,
            completionSignal: completed,
            deadline: executionDeadline
        )
        let result = ShellResult(
            stdout: String(data: stdoutCapture.finish(), encoding: .utf8) ?? "",
            stderr: String(data: stderrCapture.finish(), encoding: .utf8) ?? "",
            terminationStatus: process.terminationStatus,
            timedOut: timedOut
        )

        if timedOut {
            return .executionTimedOut(result)
        }
        if result.terminationStatus != 0 {
            return .nonZeroExit(result)
        }
        return .success(result)
    }

    /// Run a command, draining stdout and stderr concurrently to avoid pipe deadlocks.
    public static func runProcess(
        _ path: String,
        _ arguments: [String],
        timeoutSeconds: TimeInterval? = defaultTimeoutSeconds
    ) -> ShellResult? {
        execute(path, arguments, timeoutSeconds: timeoutSeconds).result
    }

    private static func waitForCompletion(
        of process: Process,
        completionSignal: DispatchSemaphore,
        deadline: DispatchTime?
    ) -> Bool {
        guard let deadline else {
            process.waitUntilExit()
            return false
        }

        if completionSignal.wait(timeout: deadline) == .timedOut {
            let descendantProcessIDs = descendants(of: process.processIdentifier)
            signal(SIGTERM, to: descendantProcessIDs)
            signal(SIGKILL, to: descendantProcessIDs)
            if process.isRunning {
                process.terminate()
            }
            if completionSignal.wait(timeout: .now() + .milliseconds(100)) == .timedOut,
               process.isRunning {
                _ = Darwin.kill(process.processIdentifier, SIGKILL)
            }
            process.waitUntilExit()
            return true
        }
        process.waitUntilExit()
        return false
    }

    /// Returns descendants that existed at timeout without signaling a process group.
    /// Keeping signals PID-targeted avoids ever affecting the collector's own group.
    private static func descendants(of rootProcessID: pid_t) -> [pid_t] {
        var pending = [rootProcessID]
        var visited = Set<pid_t>([rootProcessID])
        var descendants: [pid_t] = []

        while let processID = pending.popLast() {
            for childProcessID in directChildren(of: processID) where visited.insert(childProcessID).inserted {
                descendants.append(childProcessID)
                pending.append(childProcessID)
            }
        }
        return Array(descendants.reversed())
    }

    private static func directChildren(of processID: pid_t) -> [pid_t] {
        var processIDs = [pid_t](repeating: 0, count: 256)
        let result = processIDs.withUnsafeMutableBytes { buffer in
            proc_listchildpids(processID, buffer.baseAddress, Int32(buffer.count))
        }
        guard result > 0 else { return [] }
        return processIDs.filter { $0 > 0 && $0 != processID }
    }

    private static func signal(_ signal: Int32, to processIDs: [pid_t]) {
        for processID in processIDs {
            _ = Darwin.kill(processID, signal)
        }
    }

    /// Run a command and return stderr as a trimmed String, or nil on failure / non-zero exit.
    /// Useful for tools like `codesign -d` that write informational output to stderr.
    public static func runStderr(_ path: String, _ arguments: [String]) -> String? {
        guard case .success(let result) = execute(path, arguments) else {
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
        if case .success = execute(path, arguments) {
            return true
        }
        return false
    }
}
