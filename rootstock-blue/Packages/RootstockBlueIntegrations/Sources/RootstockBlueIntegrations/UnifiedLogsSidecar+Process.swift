import Darwin
import Foundation
import RootstockBlueCore

extension UnifiedLogsSidecar {
    static func drainOutput(
        pid: pid_t,
        stdout: Pipe,
        stderr: Pipe,
        temporaryOutput: TemporaryOutput,
        initialSnapshot: TemporarySnapshot,
        limits: Limits
    ) -> SidecarRun {
        var captured = CapturedOutput()
        var stdoutOpen = true
        var stderrOpen = true
        var failure: LimitFailure?
        var terminationRequestedAt: Date?
        var directExitStatus: Int32?
        let startedAt = Date()
        while shouldContinueDraining(directExitStatus, pid: pid, stdoutOpen: stdoutOpen, stderrOpen: stderrOpen) {
            let reads = drainPipes(stdout, stderr, captured: &captured, stdoutOpen: &stdoutOpen, stderrOpen: &stderrOpen)
            refreshExitStatus(&directExitStatus, pid: pid)
            requestTerminationIfNeeded(
                pid: pid, directExitStatus: directExitStatus, temporaryOutput: temporaryOutput,
                initialSnapshot: initialSnapshot, limits: limits, startedAt: startedAt,
                failure: &failure, terminationRequestedAt: &terminationRequestedAt
            )
            escalateTerminationIfNeeded(pid, requestedAt: terminationRequestedAt)
            let groupAlive = processGroupIsAlive(pid)
            closePipesIfGroupExited(groupAlive, stdout: stdout, stderr: stderr, stdoutOpen: &stdoutOpen, stderrOpen: &stderrOpen)
            if shouldPause(reads, directExitStatus: directExitStatus, groupAlive: groupAlive) {
                usleep(1_000)
            }
        }
        let status = directExitStatus ?? waitForExit(pid: pid)
        failure = failure ?? completedOutputFailure(temporaryOutput, initialSnapshot: initialSnapshot, limits: limits)
        return SidecarRun(captured: captured, failure: failure, exitStatus: status)
    }

    private static func shouldContinueDraining(_ directExitStatus: Int32?, pid: pid_t, stdoutOpen: Bool, stderrOpen: Bool) -> Bool {
        directExitStatus == nil || processGroupIsAlive(pid) || stdoutOpen || stderrOpen
    }

    private static func drainPipes(
        _ stdout: Pipe,
        _ stderr: Pipe,
        captured: inout CapturedOutput,
        stdoutOpen: inout Bool,
        stderrOpen: inout Bool
    ) -> (stdout: Bool, stderr: Bool) {
        (
            drain(stdout.fileHandleForReading.fileDescriptor, into: &captured.stdout, open: &stdoutOpen),
            drain(stderr.fileHandleForReading.fileDescriptor, into: &captured.stderr, open: &stderrOpen)
        )
    }

    private static func refreshExitStatus(_ status: inout Int32?, pid: pid_t) {
        guard status == nil else { return }
        status = reap(pid: pid)
    }

    private static func requestTerminationIfNeeded(
        pid: pid_t,
        directExitStatus: Int32?,
        temporaryOutput: TemporaryOutput,
        initialSnapshot: TemporarySnapshot,
        limits: Limits,
        startedAt: Date,
        failure: inout LimitFailure?,
        terminationRequestedAt: inout Date?
    ) {
        guard terminationRequestedAt == nil else { return }
        if let limitFailure = limitFailure(
            current: failure, temporaryOutput: temporaryOutput, initialSnapshot: initialSnapshot,
            limits: limits, startedAt: startedAt
        ) {
            failure = limitFailure
            requestProcessGroupTermination(pid, requestedAt: &terminationRequestedAt)
        } else if directExitStatus != nil {
            requestProcessGroupTermination(pid, requestedAt: &terminationRequestedAt)
        }
    }

    private static func limitFailure(
        current: LimitFailure?,
        temporaryOutput: TemporaryOutput,
        initialSnapshot: TemporarySnapshot,
        limits: Limits,
        startedAt: Date
    ) -> LimitFailure? {
        if let current { return current }
        if Date().timeIntervalSince(startedAt) >= limits.maximumRuntime { return .timeout }
        if temporaryOutputSize(descriptor: temporaryOutput.descriptor, expected: initialSnapshot.identity) > limits.maximumOutputBytes {
            return .outputTooLarge
        }
        return nil
    }

    private static func requestProcessGroupTermination(_ pid: pid_t, requestedAt: inout Date?) {
        requestedAt = Date()
        terminateProcessGroup(pid)
    }

    private static func escalateTerminationIfNeeded(_ pid: pid_t, requestedAt: Date?) {
        guard let requestedAt, Date().timeIntervalSince(requestedAt) >= 5 else { return }
        killProcessGroup(pid)
    }

    private static func closePipesIfGroupExited(
        _ groupAlive: Bool,
        stdout: Pipe,
        stderr: Pipe,
        stdoutOpen: inout Bool,
        stderrOpen: inout Bool
    ) {
        guard !groupAlive, stdoutOpen || stderrOpen else { return }
        stdout.fileHandleForReading.closeFile()
        stderr.fileHandleForReading.closeFile()
        stdoutOpen = false
        stderrOpen = false
    }

    private static func shouldPause(
        _ reads: (stdout: Bool, stderr: Bool), directExitStatus: Int32?, groupAlive: Bool
    ) -> Bool {
        !reads.stdout && !reads.stderr && (directExitStatus == nil || groupAlive)
    }

    private static func completedOutputFailure(
        _ temporaryOutput: TemporaryOutput, initialSnapshot: TemporarySnapshot, limits: Limits
    ) -> LimitFailure? {
        temporaryOutputSize(descriptor: temporaryOutput.descriptor, expected: initialSnapshot.identity) > limits.maximumOutputBytes
            ? .outputTooLarge
            : nil
    }

    private static func temporaryOutputSize(descriptor: Int32, expected: FileIdentity) -> Int64 {
        var info = stat()
        guard fstat(descriptor, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              FileIdentity(device: info.st_dev, inode: info.st_ino) == expected else { return Int64.max }
        return Int64(info.st_size)
    }

}
