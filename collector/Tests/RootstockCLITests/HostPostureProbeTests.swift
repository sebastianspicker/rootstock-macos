@testable import RootstockCLI
import XCTest

final class HostPostureProbeTests: XCTestCase {
    func testGatekeeperCommandFailureRecordsUnknownDiagnostic() {
        let result = ScanOrchestrator.detectGatekeeper { _, _ in nil }

        XCTAssertNil(result.value)
        XCTAssertEqual(result.error?.source, "Host Posture")
        XCTAssertTrue(result.error?.message.contains("Gatekeeper probe failed") ?? false)
        XCTAssertEqual(result.error?.recoverable, true)
    }

    func testSIPUnrecognizedOutputRecordsUnknownDiagnostic() {
        let result = ScanOrchestrator.detectSIP { _, _ in "unexpected csrutil output" }

        XCTAssertNil(result.value)
        XCTAssertTrue(result.error?.message.contains("SIP probe returned unrecognized output") ?? false)
    }

    func testFileVaultDisabledOutputIsKnownFalse() {
        let result = ScanOrchestrator.detectFileVault { _, _ in "FileVault is Off." }

        XCTAssertEqual(result.value, false)
        XCTAssertNil(result.error)
    }

    func testGatekeeperAndSIPUseSharedMacFactsParsers() {
        let gk = ScanOrchestrator.detectGatekeeper { _, _ in "assessments enabled" }
        XCTAssertEqual(gk.value, true)
        XCTAssertNil(gk.error)

        let sip = ScanOrchestrator.detectSIP { _, _ in
            "System Integrity Protection status: enabled."
        }
        XCTAssertEqual(sip.value, true)
        XCTAssertNil(sip.error)

        let fvDeferred = ScanOrchestrator.detectFileVault { _, _ in
            "Deferred enablement appears to be active."
        }
        XCTAssertEqual(fvDeferred.value, true)
    }

    func testUnreadableICloudPlistRecordsUnknownDiagnostic() {
        let result = ScanOrchestrator.detectICloudStatus { _ in nil }

        XCTAssertNil(result.signedIn)
        XCTAssertNil(result.driveEnabled)
        XCTAssertNil(result.keychainEnabled)
        XCTAssertTrue(result.error?.message.contains("iCloud probe failed") ?? false)
    }

    func testICloudSignedInWithoutServicesKeepsSyncStatusUnknown() throws {
        let plist: [String: Any] = [
            "Accounts": [
                ["AccountID": "fixture@example.com"]
            ]
        ]
        let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)

        let result = ScanOrchestrator.detectICloudStatus { _ in data }

        XCTAssertEqual(result.signedIn, true)
        XCTAssertNil(result.driveEnabled)
        XCTAssertNil(result.keychainEnabled)
        XCTAssertTrue(result.error?.message.contains("Drive and Keychain posture unknown") ?? false)
    }
}
