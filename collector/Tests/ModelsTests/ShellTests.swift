import XCTest
import Foundation
import Darwin
import Models

final class ShellTests: XCTestCase {

    private let python3Path = "/usr/bin/python3"

    func testRunReadsLargeStdoutWithoutDeadlocking() {
        let output = Shell.run(
            python3Path,
            ["-c", "import sys; sys.stdout.write('A' * 100000)"]
        )

        XCTAssertEqual(output?.count, 100000)
        XCTAssertEqual(output?.first, "A")
    }

    func testRunStderrReadsLargeStderrWithoutDeadlocking() {
        let output = Shell.runStderr(
            python3Path,
            ["-c", "import sys; sys.stderr.write('B' * 100000)"]
        )

        XCTAssertEqual(output?.count, 100000)
        XCTAssertEqual(output?.first, "B")
    }

    func testRunReturnsNilWhenTimeoutExpires() {
        let output = Shell.run(
            python3Path,
            ["-c", "import time; time.sleep(5)"],
            timeoutSeconds: 0.1
        )

        XCTAssertNil(output)
    }

    func testRunProcessTimeoutTerminatesStdoutOnlyChild() throws {
        let result = try runTimedOutChild(
            body: "sys.stdout.write('stdout-before-timeout\\n'); sys.stdout.flush()"
        )

        XCTAssertTrue(result.stdout.contains("stdout-before-timeout"))
        XCTAssertEqual(result.stderr, "")
    }

    func testRunProcessTimeoutTerminatesStderrOnlyChild() throws {
        let result = try runTimedOutChild(
            body: "sys.stderr.write('stderr-before-timeout\\n'); sys.stderr.flush()"
        )

        XCTAssertEqual(result.stdout, "")
        XCTAssertTrue(result.stderr.contains("stderr-before-timeout"))
    }

    func testRunProcessTimeoutTerminatesChildWithBothStreams() throws {
        let result = try runTimedOutChild(
            body: """
            sys.stdout.write('stdout-before-timeout\\n')
            sys.stdout.flush()
            sys.stderr.write('stderr-before-timeout\\n')
            sys.stderr.flush()
            """
        )

        XCTAssertTrue(result.stdout.contains("stdout-before-timeout"))
        XCTAssertTrue(result.stderr.contains("stderr-before-timeout"))
    }

    func testRunProcessTimeoutTerminatesChildWithNoOutput() throws {
        let result = try runTimedOutChild(body: "pass")

        XCTAssertEqual(result.stdout, "")
        XCTAssertEqual(result.stderr, "")
    }

    func testRunProcessTimeoutDoesNotLeaveChildWritingAfterReturn() throws {
        let marker = temporaryPath("shell-late-write")
        defer { try? FileManager.default.removeItem(atPath: marker) }

        let script = """
        import pathlib
        import sys
        import time

        marker = pathlib.Path(sys.argv[1])
        time.sleep(0.3)
        marker.write_text('late-write')
        time.sleep(5)
        """

        let result = Shell.runProcess(
            python3Path,
            ["-c", script, marker],
            timeoutSeconds: 0.1
        )

        XCTAssertEqual(result?.timedOut, true)
        waitForPotentialLateWrite(at: marker)
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker))
    }

    func testRunProcessCompletesBeforeNearBoundaryTimeout() {
        let result = Shell.runProcess(
            python3Path,
            ["-c", "import time; time.sleep(0.05); print('completed-before-timeout')"],
            timeoutSeconds: 1
        )

        XCTAssertEqual(result?.timedOut, false)
        XCTAssertEqual(result?.terminationStatus, 0)
        XCTAssertEqual(result?.stdout.trimmingCharacters(in: .whitespacesAndNewlines), "completed-before-timeout")
    }

    func testRunProcessDrainsStdoutAndStderrConcurrently() {
        let result = Shell.runProcess(
            python3Path,
            ["-c", "import sys; sys.stdout.write('A' * 100000); sys.stderr.write('B' * 100000)"],
            timeoutSeconds: 2
        )

        XCTAssertEqual(result?.terminationStatus, 0)
        XCTAssertEqual(result?.stdout.count, 100000)
        XCTAssertEqual(result?.stderr.count, 100000)
    }

    private func runTimedOutChild(body: String, file: StaticString = #filePath, line: UInt = #line) throws -> ShellResult {
        let pidPath = temporaryPath("shell-child-pid")
        defer { try? FileManager.default.removeItem(atPath: pidPath) }

        let script = """
        import os
        import pathlib
        import sys
        import time

        pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))
        \(body)
        time.sleep(5)
        """

        guard let result = Shell.runProcess(
            python3Path,
            ["-c", script, pidPath],
            timeoutSeconds: 0.1
        ) else {
            XCTFail("Expected timed-out shell result", file: file, line: line)
            throw ShellTestError.missingResult
        }

        XCTAssertTrue(result.timedOut, file: file, line: line)
        let pidText = try String(contentsOfFile: pidPath, encoding: .utf8)
        guard let pid = pid_t(pidText.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            XCTFail("Expected child pid in \(pidPath)", file: file, line: line)
            throw ShellTestError.missingPID
        }
        XCTAssertFalse(isProcessRunning(pid), "Child process \(pid) still running after timeout", file: file, line: line)
        return result
    }

    private func temporaryPath(_ prefix: String) -> String {
        (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("\(prefix)-\(UUID().uuidString)")
    }

    private func isProcessRunning(_ pid: pid_t) -> Bool {
        if kill(pid, 0) == 0 {
            return true
        }
        return errno == EPERM
    }

    private func waitForPotentialLateWrite(at path: String) {
        let deadline = Date().addingTimeInterval(1)
        while Date() < deadline {
            if FileManager.default.fileExists(atPath: path) {
                return
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
    }

    private enum ShellTestError: Error {
        case missingResult
        case missingPID
    }
}
