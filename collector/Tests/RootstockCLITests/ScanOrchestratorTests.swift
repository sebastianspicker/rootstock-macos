import XCTest
@testable import Models
@testable import RootstockCLI

final class ScanOrchestratorTests: XCTestCase {
    func testModuleConfigNormalizesWhitespaceAndDuplicates() throws {
        let config = try ScanOrchestrator.ModuleConfig.from(" tcc, entitlements, tcc ")

        XCTAssertEqual(config.selectedModuleNames, ["entitlements", "tcc"])
        XCTAssertTrue(config.includes(.tcc))
        XCTAssertTrue(config.includes(.entitlements))
        XCTAssertFalse(config.includes(.xpc))
    }

    func testModuleConfigAllSelectsEveryModule() throws {
        let config = try ScanOrchestrator.ModuleConfig.from("all, tcc")

        XCTAssertEqual(config.selectedModuleNames, Set(RootstockModuleID.allCases.map(\.rawValue)))
    }

    func testModuleConfigRejectsSortedUnknownModules() {
        XCTAssertThrowsError(try ScanOrchestrator.ModuleConfig.from("tcc, zebra, alpha")) { error in
            guard case let .unknownModules(modules) = error as? RootstockModuleConfigError else {
                return XCTFail("Expected unknown module error, got \(error)")
            }
            XCTAssertEqual(modules, ["alpha", "zebra"])
        }
    }

    func testApplicationEnrichmentsRequireEntitlements() {
        for module in ["sandbox", "quarantine", "sandbox, quarantine"] {
            XCTAssertThrowsError(try ScanOrchestrator.ModuleConfig.from(module)) { error in
                guard case let .missingPrerequisites(messages) = error as? RootstockModuleConfigError else {
                    return XCTFail("Expected entitlement prerequisite error, got \(error)")
                }
                XCTAssertFalse(messages.isEmpty)
                XCTAssertTrue(messages.allSatisfy { $0.contains("requires module 'entitlements'") })
            }
        }
    }

    func testInjectedExecutionReturnsCanonicalScanWithoutHostCollection() async throws {
        let expected = canonicalScan()
        let orchestrator = ScanOrchestrator(
            verbose: false,
            execution: .injected { config in
                XCTAssertTrue(config.includes(.tcc))
                return expected
            }
        )
        let config = try ScanOrchestrator.ModuleConfig.from("tcc")

        let actual = await orchestrator.run(config: config)

        XCTAssertEqual(actual.scanId, "canonical-scan")
        XCTAssertEqual(actual.timestamp, "2026-09-04T00:00:00Z")
        XCTAssertEqual(actual.hostname, "fixture-host")
        XCTAssertEqual(actual.collectorVersion, "0.1.0-alpha.1")
        XCTAssertTrue(actual.applications.isEmpty)
        XCTAssertTrue(actual.errors.isEmpty)
    }

    private func canonicalScan() -> ScanResult {
        ScanResult(
            metadata: .init(
                scanId: "canonical-scan",
                timestamp: "2026-09-04T00:00:00Z",
                hostname: "fixture-host",
                macosVersion: "macOS 26.0",
                collectorVersion: "0.1.0-alpha.1"
            ),
            elevation: .init(isRoot: false, hasFda: false),
            errors: []
        )
    }
}
