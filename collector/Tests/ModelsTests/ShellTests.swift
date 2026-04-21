import XCTest
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
}
