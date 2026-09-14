import Darwin
import Foundation
import RootstockBlueCore

/// Mandiant macos-UnifiedLogs sidecar wrapper - never rewrite the Rust parser in-process.
public enum UnifiedLogsSidecar {
    public static var binaryEnvironmentKey: String { "ROOTSTOCK_BLUE_ULS_BINARY" }

    /// Resource bounds for an external parser. The defaults are deliberately
    /// generous for an operator-selected logarchive while still bounding a
    /// wedged or malicious sidecar.
    public struct Limits: Sendable, Equatable {
        public var maximumRuntime: TimeInterval
        public var maximumOutputBytes: Int64

        public init(maximumRuntime: TimeInterval = 30 * 60, maximumOutputBytes: Int64 = 8 * 1024 * 1024 * 1024) {
            self.maximumRuntime = maximumRuntime
            self.maximumOutputBytes = maximumOutputBytes
        }
    }

    public enum Status: Sendable, Equatable {
        case notConfigured
        case binaryMissing(path: String)
        case ready(path: String)
    }

    public static func resolveBinary() -> URL? {
        guard let url = configuredBinaryURL(), isRegularExecutableFile(at: url) else { return nil }
        return url
    }

    public static func status() -> Status {
        guard let url = configuredBinaryURL() else {
            return .notConfigured
        }
        return isRegularExecutableFile(at: url) ? .ready(path: url.path) : .binaryMissing(path: url.path)
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
    public static func parse(logarchive: URL, outputJSONL: URL, limits: Limits = Limits()) throws {
        guard let bin = resolveBinary() else {
            throw RootstockBlueError.notImplemented(statusMessage())
        }
        try validateLogarchive(logarchive)
        guard limits.maximumRuntime > 0, limits.maximumOutputBytes >= 0 else {
            throw RootstockBlueError.io("ULS limits must be positive runtime and non-negative output size")
        }

        let temporaryOutput = try temporarySibling(for: outputJSONL)
        defer {
            _ = close(temporaryOutput.descriptor)
            try? FileManager.default.removeItem(at: temporaryOutput.url)
        }
        let initialSnapshot = try temporarySnapshot(descriptor: temporaryOutput.descriptor)
        let err = Pipe()
        let out = Pipe()
        try setNonblocking(out.fileHandleForReading.fileDescriptor)
        try setNonblocking(err.fileHandleForReading.fileDescriptor)
        let pid: pid_t
        do {
            pid = try spawnSidecar(
                binary: bin,
                arguments: [logarchive.path, "--output", temporaryOutput.url.path],
                stdout: out.fileHandleForWriting.fileDescriptor,
                stderr: err.fileHandleForWriting.fileDescriptor
            )
        } catch {
            out.fileHandleForWriting.closeFile()
            err.fileHandleForWriting.closeFile()
            throw error
        }
        out.fileHandleForWriting.closeFile()
        err.fileHandleForWriting.closeFile()

        let run = drainOutput(
            pid: pid,
            stdout: out,
            stderr: err,
            temporaryOutput: temporaryOutput,
            initialSnapshot: initialSnapshot,
            limits: limits
        )

        if let failure = run.failure {
            throw RootstockBlueError.io("ULS sidecar \(failure.description). stderr=\(run.captured.stderr.description(limit: 500)) stdout=\(run.captured.stdout.description(limit: 200))")
        }
        if run.exitStatus != 0 {
            // If tool wrote output despite non-zero, still surface error honestly.
            throw RootstockBlueError.io(
                "ULS sidecar exited \(run.exitStatus). stderr=\(run.captured.stderr.description(limit: 500)) stdout=\(run.captured.stdout.description(limit: 200))"
            )
        }
        try validateCompletedOutput(
            temporaryOutput,
            expected: initialSnapshot,
            maximumOutputBytes: limits.maximumOutputBytes
        )
        try publish(temporaryOutput.url, to: outputJSONL, expected: initialSnapshot)
    }

    private static func configuredBinaryURL() -> URL? {
        guard let path = ProcessInfo.processInfo.environment[binaryEnvironmentKey], !path.isEmpty else {
            return nil
        }
        return URL(fileURLWithPath: path)
    }

    /// Reject links, directories, and special files before handing the URL to `Process`.
    private static func isRegularExecutableFile(at url: URL) -> Bool {
        var info = stat()
        guard lstat(url.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else { return false }
        return (info.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0
    }

    private static func validateLogarchive(_ logarchive: URL) throws {
        var info = stat()
        guard lstat(logarchive.path, &info) == 0 else {
            throw RootstockBlueError.io("logarchive not found: \(logarchive.path)")
        }
        guard (info.st_mode & S_IFMT) == S_IFDIR else {
            throw RootstockBlueError.io("logarchive must be a real directory, not a symbolic link or file: \(logarchive.path)")
        }
    }

    private static func temporarySibling(for destination: URL) throws -> TemporaryOutput {
        try validateDestination(destination, createParent: true)
        let parent = destination.deletingLastPathComponent().standardizedFileURL
        var template = parent
            .appendingPathComponent(".\(destination.lastPathComponent).rootstock-uls-XXXXXX")
            .path
            .utf8CString
        let descriptor = template.withUnsafeMutableBufferPointer { mkstemp($0.baseAddress!) }
        guard descriptor >= 0 else {
            throw RootstockBlueError.io("cannot create temporary ULS output")
        }
        let path = template.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
        return TemporaryOutput(url: URL(fileURLWithPath: path), descriptor: descriptor)
    }

    private static func publish(_ temporaryOutput: URL, to destination: URL, expected: TemporarySnapshot) throws {
        try validateDestination(destination, createParent: false)
        guard let snapshot = try? temporarySnapshot(at: temporaryOutput), snapshot.identity == expected.identity else {
            throw RootstockBlueError.io("ULS sidecar did not produce a real regular output file")
        }
        guard link(temporaryOutput.path, destination.path) == 0 else {
            if errno == EEXIST {
                throw RootstockBlueError.io("refusing to overwrite existing ULS output: \(destination.path)")
            }
            throw RootstockBlueError.io("cannot publish ULS output")
        }
    }

    private static func validateDestination(_ destination: URL, createParent: Bool) throws {
        let target = destination.standardizedFileURL
        let resolvedTarget = resolveExistingAncestor(of: target)
        guard !hasCasePackageAncestor(target), !hasCasePackageAncestor(resolvedTarget) else {
            throw RootstockBlueError.io("ULS output must be outside a case package")
        }
        let parent = target.deletingLastPathComponent()
        if createParent {
            try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        }
        guard isRealDirectory(at: parent) else {
            throw RootstockBlueError.io("ULS output parent must be a real directory")
        }
        if pathExists(destination) {
            throw RootstockBlueError.io("refusing to overwrite existing ULS output: \(destination.path)")
        }
    }

    private static func hasCasePackageAncestor(_ url: URL) -> Bool {
        var candidate = url
        while candidate.path != "/" {
            if candidate.pathExtension.lowercased() == "rsbcase" { return true }
            let parent = candidate.deletingLastPathComponent()
            if parent.path == candidate.path { break }
            candidate = parent
        }
        return false
    }

    /// Resolve the deepest existing component so a non-existent final output
    /// below a symlinked case directory cannot bypass the case boundary.
    private static func resolveExistingAncestor(of url: URL) -> URL {
        var candidate = url
        var suffix: [String] = []
        while !pathExists(candidate), candidate.path != "/" {
            suffix.append(candidate.lastPathComponent)
            let parent = candidate.deletingLastPathComponent()
            if parent.path == candidate.path { break }
            candidate = parent
        }
        var resolved = candidate.resolvingSymlinksInPath().standardizedFileURL
        for component in suffix.reversed() {
            resolved.appendPathComponent(component)
        }
        return resolved.standardizedFileURL
    }

    private static func pathExists(_ url: URL) -> Bool {
        var info = stat()
        return lstat(url.path, &info) == 0
    }

    private static func isRegularFile(at url: URL) -> Bool {
        var info = stat()
        return lstat(url.path, &info) == 0 && (info.st_mode & S_IFMT) == S_IFREG
    }

    private static func isRealDirectory(at url: URL) -> Bool {
        var info = stat()
        return lstat(url.path, &info) == 0 && (info.st_mode & S_IFMT) == S_IFDIR
    }

    /// `POSIX_SPAWN_SETPGROUP` with pgroup zero creates a fresh process group
    /// as part of spawning, before the executable can fork a descendant.
    private static func spawnSidecar(binary: URL, arguments: [String], stdout: Int32, stderr: Int32) throws -> pid_t {
        var actions: posix_spawn_file_actions_t? = nil
        guard posix_spawn_file_actions_init(&actions) == 0 else {
            throw RootstockBlueError.io("cannot configure ULS sidecar file actions")
        }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawn_file_actions_adddup2(&actions, stdout, STDOUT_FILENO) == 0,
              posix_spawn_file_actions_adddup2(&actions, stderr, STDERR_FILENO) == 0,
              posix_spawn_file_actions_addclose(&actions, stdout) == 0,
              posix_spawn_file_actions_addclose(&actions, stderr) == 0 else {
            throw RootstockBlueError.io("cannot configure ULS sidecar output")
        }

        var attributes: posix_spawnattr_t? = nil
        guard posix_spawnattr_init(&attributes) == 0 else {
            throw RootstockBlueError.io("cannot configure ULS sidecar process group")
        }
        defer { posix_spawnattr_destroy(&attributes) }
        guard posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETPGROUP)) == 0,
              posix_spawnattr_setpgroup(&attributes, 0) == 0 else {
            throw RootstockBlueError.io("cannot isolate ULS sidecar process group")
        }

        let invocation = [binary.path] + arguments
        let storage = invocation.map { strdup($0) }
        defer { storage.forEach { free($0) } }
        var argv = storage + [nil]
        var pid: pid_t = 0
        let result = binary.path.withCString { executable in
            posix_spawn(&pid, executable, &actions, &attributes, &argv, environ)
        }
        guard result == 0 else {
            throw RootstockBlueError.io("cannot launch ULS sidecar: \(String(cString: strerror(result)))")
        }
        return pid
    }

    static func terminateProcessGroup(_ pid: pid_t) {
        if kill(-pid, SIGTERM) != 0, errno != ESRCH { /* rechecked by the bounded drain loop */ }
    }

    static func killProcessGroup(_ pid: pid_t) {
        if kill(-pid, SIGKILL) != 0, errno != ESRCH { /* rechecked by the bounded drain loop */ }
    }

    static func processGroupIsAlive(_ pid: pid_t) -> Bool {
        if kill(-pid, 0) == 0 { return true }
        return errno == EPERM
    }

    static func reap(pid: pid_t) -> Int32? {
        var status: Int32 = 0
        let result = waitpid(pid, &status, WNOHANG)
        if result == pid { return exitStatus(status) }
        return nil
    }

    static func waitForExit(pid: pid_t) -> Int32 {
        var status: Int32 = 0
        while waitpid(pid, &status, 0) < 0 {
            if errno != EINTR { return -1 }
        }
        return exitStatus(status)
    }

    private static func exitStatus(_ status: Int32) -> Int32 {
        let signal = status & 0x7F
        if signal == 0 { return (status >> 8) & 0xFF }
        if signal != 0x7F { return 128 + signal }
        return -1
    }

    private static func temporarySnapshot(descriptor: Int32) throws -> TemporarySnapshot {
        var info = stat()
        guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else {
            throw RootstockBlueError.io("ULS temporary output is not a regular file")
        }
        return TemporarySnapshot(identity: FileIdentity(device: info.st_dev, inode: info.st_ino), size: Int64(info.st_size))
    }

    private static func temporarySnapshot(at url: URL) throws -> TemporarySnapshot {
        var info = stat()
        guard lstat(url.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else {
            throw RootstockBlueError.io("ULS sidecar did not produce a real regular output file")
        }
        return TemporarySnapshot(identity: FileIdentity(device: info.st_dev, inode: info.st_ino), size: Int64(info.st_size))
    }

    private static func validateCompletedOutput(
        _ temporaryOutput: TemporaryOutput,
        expected: TemporarySnapshot,
        maximumOutputBytes: Int64
    ) throws {
        let descriptorSnapshot = try temporarySnapshot(descriptor: temporaryOutput.descriptor)
        let pathSnapshot = try temporarySnapshot(at: temporaryOutput.url)
        guard descriptorSnapshot.identity == expected.identity,
              pathSnapshot.identity == expected.identity,
              descriptorSnapshot.size == pathSnapshot.size,
              descriptorSnapshot.size <= maximumOutputBytes else {
            throw RootstockBlueError.io("ULS sidecar output changed or exceeded its output size limit")
        }
    }

    private static func setNonblocking(_ descriptor: Int32) throws {
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
            throw RootstockBlueError.io("cannot configure ULS sidecar output pipe")
        }
    }

    @discardableResult
    static func drain(_ descriptor: Int32, into capture: inout OutputCapture, open: inout Bool) -> Bool {
        var buffer = [UInt8](repeating: 0, count: 16 * 1024)
        var readAny = false
        while true {
            let count = read(descriptor, &buffer, buffer.count)
            if count > 0 {
                capture.append(buffer, count: Int(count))
                readAny = true
                continue
            }
            if count == 0 {
                open = false
                return readAny
            }
            if errno == EINTR { continue }
            if errno == EAGAIN || errno == EWOULDBLOCK { return readAny }
            open = false
            return readAny
        }
    }

    struct CapturedOutput {
        var stdout = OutputCapture()
        var stderr = OutputCapture()
    }

    struct SidecarRun {
        let captured: CapturedOutput
        let failure: LimitFailure?
        let exitStatus: Int32
    }

    struct TemporaryOutput {
        let url: URL
        let descriptor: Int32
    }

    struct FileIdentity: Equatable {
        let device: dev_t
        let inode: ino_t
    }

    struct TemporarySnapshot {
        let identity: FileIdentity
        let size: Int64
    }

    enum LimitFailure {
        case timeout
        case outputTooLarge

        var description: String {
            switch self {
            case .timeout: return "exceeded its runtime limit"
            case .outputTooLarge: return "exceeded its output size limit"
            }
        }
    }

    struct OutputCapture {
        private static let capacity = 64 * 1024
        private var prefix = Data()
        private var discardedBytes = 0

        mutating func append(_ buffer: [UInt8], count: Int) {
            let available = Self.capacity - prefix.count
            if available > 0 {
                prefix.append(contentsOf: buffer.prefix(min(available, count)))
            }
            discardedBytes += max(0, count - available)
        }

        func description(limit: Int) -> String {
            let text = String(data: prefix.prefix(limit), encoding: .utf8) ?? "<non-UTF8 output>"
            return discardedBytes > 0 ? "\(text) [truncated]" : text
        }
    }
}
