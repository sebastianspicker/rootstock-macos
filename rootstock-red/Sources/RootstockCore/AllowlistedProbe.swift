import Foundation

/// Result of a single allowlisted status probe.
public struct AllowlistedProbeResult: Sendable, Equatable {
    public var executable: String
    public var arguments: [String]
    public var exitCode: Int32?
    public var stdout: String
    public var stderr: String
    public var timedOut: Bool
    public var errorDescription: String?

    public init(
        executable: String,
        arguments: [String],
        exitCode: Int32? = nil,
        stdout: String = "",
        stderr: String = "",
        timedOut: Bool = false,
        errorDescription: String? = nil
    ) {
        self.executable = executable
        self.arguments = arguments
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
        self.timedOut = timedOut
        self.errorDescription = errorDescription
    }

    public var combinedOutput: String {
        let out = stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        let err = stderr.trimmingCharacters(in: .whitespacesAndNewlines)
        if out.isEmpty { return err }
        if err.isEmpty { return out }
        return out + "\n" + err
    }
}

/// Hard-coded, read-only status CLI allowlist for assess mode.
///
/// Unlike `ProcessRunner` (lab/agent only), this may run in assess - but only for the
/// exact (executable, arguments) pairs listed below. No arbitrary shell, no PATH lookup.
public enum AllowlistedProbe: Sendable {
    private struct ProcessSetup {
        let process: Process
        let out: Pipe
        let err: Pipe
    }

    public enum Command: String, Sendable, CaseIterable {
        case csrutilStatus
        case spctlStatus
        case fdesetupStatus

        public var executable: String {
            switch self {
            case .csrutilStatus: return "/usr/bin/csrutil"
            case .spctlStatus: return "/usr/sbin/spctl"
            case .fdesetupStatus: return "/usr/bin/fdesetup"
            }
        }

        public var arguments: [String] {
            switch self {
            case .csrutilStatus: return ["status"]
            case .spctlStatus: return ["--status"]
            case .fdesetupStatus: return ["status"]
            }
        }
    }

    /// Default wall-clock timeout for status probes (seconds).
    public static let defaultTimeoutSeconds: TimeInterval = 3

    /// Run a single allowlisted status command with a short timeout.
    public static func run(
        _ command: Command,
        timeoutSeconds: TimeInterval = defaultTimeoutSeconds
    ) -> AllowlistedProbeResult {
        let executable = command.executable
        let arguments = command.arguments
        guard FileManager.default.isExecutableFile(atPath: executable) else {
            return failure(executable, arguments, "executable missing or not executable")
        }
        let setup = configuredProcess(executable, arguments)
        if let errorDescription = launch(setup.process) {
            return failure(executable, arguments, errorDescription)
        }
        return result(for: setup, executable: executable, arguments: arguments, timeoutSeconds: timeoutSeconds)
    }

    private static func configuredProcess(_ executable: String, _ arguments: [String]) -> ProcessSetup {
        let process = Process(); let out = Pipe(); let err = Pipe()
        process.executableURL = URL(fileURLWithPath: executable); process.arguments = arguments
        process.standardOutput = out; process.standardError = err; process.standardInput = FileHandle.nullDevice
        return ProcessSetup(process: process, out: out, err: err)
    }

    private static func launch(_ process: Process) -> String? {
        do { try process.run(); return nil }
        catch { return "failed to launch: \(error.localizedDescription)" }
    }

    private static func result(for setup: ProcessSetup, executable: String, arguments: [String], timeoutSeconds: TimeInterval) -> AllowlistedProbeResult {
        let deadline = Date().addingTimeInterval(timeoutSeconds)
        while setup.process.isRunning, Date() < deadline { Thread.sleep(forTimeInterval: 0.05) }
        if setup.process.isRunning { return timeout(setup, executable, arguments, timeoutSeconds) }
        return completed(setup, executable, arguments)
    }

    private static func timeout(_ setup: ProcessSetup, _ executable: String, _ arguments: [String], _ seconds: TimeInterval) -> AllowlistedProbeResult {
        setup.process.terminate(); Thread.sleep(forTimeInterval: 0.05); if setup.process.isRunning { setup.process.interrupt() }
        _ = try? setup.out.fileHandleForReading.readToEnd(); _ = try? setup.err.fileHandleForReading.readToEnd()
        return AllowlistedProbeResult(executable: executable, arguments: arguments, timedOut: true, errorDescription: "timed out after \(seconds)s")
    }

    private static func completed(_ setup: ProcessSetup, _ executable: String, _ arguments: [String]) -> AllowlistedProbeResult {
        let stdout = String(data: setup.out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let stderr = String(data: setup.err.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        return AllowlistedProbeResult(executable: executable, arguments: arguments, exitCode: setup.process.terminationStatus, stdout: stdout, stderr: stderr)
    }

    private static func failure(_ executable: String, _ arguments: [String], _ message: String) -> AllowlistedProbeResult { AllowlistedProbeResult(executable: executable, arguments: arguments, errorDescription: message) }
}
