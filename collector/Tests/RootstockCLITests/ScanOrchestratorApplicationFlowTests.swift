@testable import RootstockCLI
import Models
import XCTest

final class ScanOrchestratorApplicationFlowTests: XCTestCase {
    func testConcurrentApplicationEnrichmentMergeUsesApplicationPath() {
        let first = application(name: "First", bundleId: "com.example.first", path: "/Applications/First.app")
        let second = application(name: "Second", bundleId: "com.example.second", path: "/Applications/Second.app")
        let firstQuarantine = QuarantineInfo(
            hasQuarantineFlag: true,
            quarantineAgent: "com.apple.Safari"
        )
        let secondQuarantine = QuarantineInfo(
            hasQuarantineFlag: true,
            quarantineAgent: "com.apple.mail"
        )

        let sandboxApplications = [
            first.with(sandboxProfile: SandboxProfile(bundleId: first.bundleId, profileSource: "test")),
            second.with(sandboxProfile: SandboxProfile(bundleId: second.bundleId, profileSource: "test"))
        ]
        let quarantineApplications = [
            second.with(quarantineInfo: secondQuarantine),
            first.with(quarantineInfo: firstQuarantine)
        ]

        let merged = ScanOrchestrator.mergeApplicationEnrichments(
            sandboxApplications: sandboxApplications,
            quarantineApplications: quarantineApplications
        )

        XCTAssertEqual(merged.map(\.path), [first.path, second.path])
        XCTAssertEqual(merged[0].sandboxProfile?.bundleId, first.bundleId)
        XCTAssertEqual(merged[1].sandboxProfile?.bundleId, second.bundleId)
        XCTAssertEqual(merged[0].quarantineInfo?.quarantineAgent, "com.apple.Safari")
        XCTAssertEqual(merged[1].quarantineInfo?.quarantineAgent, "com.apple.mail")
    }

    private func application(name: String, bundleId: String, path: String) -> Application {
        Application(
            identity: Application.Identity(
                name: name,
                bundleId: bundleId,
                path: path,
                version: nil
            ),
            flags: Application.Flags(isElectron: false, isSystem: false),
            signing: Application.Signing()
        )
    }
}
