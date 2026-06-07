@testable import RootstockCLI
import Models
import XCTest

final class CompletionStatusTests: XCTestCase {
    func testCleanScanIsReportedComplete() {
        let lines = RootstockCommand.completionLines(
            for: scanResult(errors: []),
            output: "/tmp/scan.json"
        )

        XCTAssertEqual(lines.count, 1)
        XCTAssertTrue(lines[0].hasPrefix("Scan complete."))
        XCTAssertFalse(lines[0].contains("partial"))
    }

    func testRecoverableErrorsAreReportedPartialWithWarningCount() {
        let lines = RootstockCommand.completionLines(
            for: scanResult(errors: [
                CollectionError(source: "TCC Database", message: "fixture error", recoverable: true)
            ]),
            output: "/tmp/scan.json"
        )

        XCTAssertEqual(lines.count, 2)
        XCTAssertTrue(lines[0].hasPrefix("Scan partial."))
        XCTAssertFalse(lines[0].contains("Scan complete"))
        XCTAssertTrue(lines[1].contains("1 warning(s)"))
        XCTAssertTrue(lines[1].contains("scan is partial"))
    }

    func testNonRecoverableErrorsAreReportedFailedNotPartial() {
        let lines = RootstockCommand.completionLines(
            for: scanResult(errors: [
                CollectionError(source: "Export", message: "fixture fatal error", recoverable: false),
                CollectionError(source: "TCC Database", message: "fixture warning", recoverable: true),
            ]),
            output: "/tmp/scan.json"
        )

        XCTAssertEqual(lines.count, 2)
        XCTAssertTrue(lines[0].hasPrefix("Scan failed."))
        XCTAssertFalse(lines[0].contains("Scan partial"))
        XCTAssertTrue(lines[0].contains("Output: /tmp/scan.json"))
        XCTAssertTrue(lines[1].contains("1 error(s), 1 warning(s)"))
        XCTAssertTrue(lines[1].contains("scan failed"))
    }

    private func scanResult(errors: [CollectionError]) -> ScanResult {
        ScanResult(
            metadata: ScanResult.Metadata(
                scanId: "test-scan",
                timestamp: "2026-05-26T00:00:00Z",
                hostname: "test-host",
                macosVersion: "macOS 15.0",
                collectorVersion: RootstockCommand.collectorVersion
            ),
            elevation: ElevationInfo(isRoot: false, hasFda: false),
            errors: errors
        )
    }
}
