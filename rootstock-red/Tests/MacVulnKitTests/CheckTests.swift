import XCTest
import RootstockCore
import MacEnumKit
import MacArtifactKit
import MacReportKit
@testable import MacVulnKit

final class CheckTests: XCTestCase {
    func testHostIdentityCheck() async throws {
        var state = CollectedState()
        state.host = HostState(
            hostname: "test-host",
            username: "tester",
            osVersion: "14.0.0",
            arch: "arm64",
            processArch: "arm64"
        )
        let findings = try await HostIdentityCheck().evaluate(state: state, context: .assess())
        XCTAssertEqual(findings.count, 1)
        XCTAssertEqual(findings.first?.id, HostIdentityCheck.id)
    }

    func testAllChecksRegistered() {
        let ids = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        let required = [
            "rootstock.check.host.identity",
            "rootstock.check.sec.tools_detected",
            "rootstock.check.persist.user_launchagents_present",
            "rootstock.check.persist.system_launchd_inventory",
            "rootstock.check.auth.cred_paths_present",
            "rootstock.check.tcc.preflight_summary",
            "rootstock.check.lool.inventory",
            "rootstock.check.protections.posture",
            "rootstock.check.persist.btm_loginitems",
            "rootstock.check.browser.meta_paths",
            "rootstock.check.codesign.inject_surface",
            "rootstock.check.mdm.vendor_hints",
            "rootstock.check.mdm.profiles",
            "rootstock.check.identity.posture",
            "rootstock.check.lool.planner",
            "rootstock.check.network.sharing_posture",
        ] + AttackVectorPlane.ids
        for id in required {
            XCTAssertTrue(ids.contains(id), "missing check \(id)")
        }
    }

    func testFullRegistryRuns() async {
        let registry = VulnModuleRegistry.fullRegistry()
        let context = EvaluationContext.assess(profile: .quick)
        let state = await CollectionRunner.run(registry: registry, context: context)
        let findings = await CheckRunner.run(registry: registry, state: state, context: context)
        XCTAssertNotNil(state.host)
        XCTAssertFalse(findings.isEmpty)
    }

    func testAssessPipelineStandard() async {
        let result = await AssessPipeline.run(profile: .standard)
        let state = result.state
        let findings = result.findings
        let ledger = result.ledger

        assertPipelineThemes(in: findings)
        assertStructuredPipelineState(state, findingIDs: Set(findings.map(\.id)))
        await assertArtifactLedgerIsPopulated(ledger)
        assertPipelineFindingSafety(findings)
    }

    private func assertPipelineThemes(in findings: [Finding]) {
        let ids = Set(findings.map(\.id))
        let categories = Set(findings.map(\.category))

        XCTAssertTrue(ids.contains("rootstock.check.host.identity"), "missing host identity finding")
        XCTAssertTrue(categories.contains(.host))
        assertSecurityOrPersistenceTheme(ids: ids, categories: categories)
        assertTCCAuthOrLOOLTheme(ids: ids, categories: categories)
    }

    private func assertSecurityOrPersistenceTheme(ids: Set<String>, categories: Set<FindingCategory>) {
        XCTAssertTrue(
            ids.contains("rootstock.check.sec.tools_detected")
                || ids.contains("rootstock.check.sec.tools_detected.none")
                || ids.contains(where: { $0.hasPrefix("rootstock.check.persist.") })
                || categories.contains(.securityProduct)
                || categories.contains(.persist),
            "expected security product or persist findings; ids=\(ids)"
        )
    }

    private func assertTCCAuthOrLOOLTheme(ids: Set<String>, categories: Set<FindingCategory>) {
        XCTAssertTrue(
            ids.contains("rootstock.check.tcc.preflight_summary")
                || ids.contains(where: { $0.hasPrefix("rootstock.check.auth.") })
                || ids.contains("rootstock.check.lool.inventory")
                || categories.contains(.tcc)
                || categories.contains(.auth)
                || categories.contains(.lool),
            "expected tcc/auth/lool findings; ids=\(ids)"
        )
    }

    private func assertStructuredPipelineState(_ state: CollectedState, findingIDs: Set<String>) {
        XCTAssertNotNil(state.protections, "protections state missing")
        XCTAssertFalse(state.loobins.isEmpty, "loobins inventory empty")
        XCTAssertNotNil(state.identity, "identity posture missing")
        XCTAssertFalse(state.identity?.notes.joined().localizedCaseInsensitiveContains("scaffold stub") ?? true)
        XCTAssertTrue(findingIDs.contains("rootstock.check.protections.posture") || state.protections != nil)
        XCTAssertTrue(findingIDs.contains("rootstock.check.identity.posture") || state.identity != nil)
        XCTAssertFalse(state.lolPlans.isEmpty, "lolPlans empty under standard profile")
    }

    private func assertArtifactLedgerIsPopulated(_ ledger: ArtifactLedger) async {
        let records = await ledger.allRecords()
        XCTAssertFalse(records.isEmpty, "artifact ledger empty after pipeline")
    }

    private func assertPipelineFindingSafety(_ findings: [Finding]) {
        for finding in findings {
            XCTAssertTrue(finding.dryRunSafe)
            XCTAssertFalse(finding.evidence.isEmpty, "finding \(finding.id) missing evidence")
            XCTAssertFalse(finding.attackTechniques.isEmpty, "finding \(finding.id) missing ATT&CK tags")
            XCTAssertNotNil(finding.opsecScore, "finding \(finding.id) missing OPSEC score after pipeline")
            XCTAssertTrue(finding.evidence.contains { $0.type == "opsec" }, "finding \(finding.id) missing opsec evidence note")
        }
    }

    func testArtifactLedgerRecordStatePaths() async {
        var state = CollectedState()
        state.launchAgents = [
            LaunchAgentEntry(label: "x", path: "/tmp/LaunchAgents/x.plist"),
        ]
        state.credPaths = [
            CredPathHit(kind: "ssh", path: "/tmp/.ssh/id_rsa", exists: true),
            CredPathHit(kind: "missing", path: "/tmp/nope", exists: false),
        ]
        state.loobins = [
            LOOBinHit(name: "osascript", path: "/usr/bin/osascript", present: true),
        ]
        state.tcc = TCCState(
            fullDiskAccessLikely: false,
            notes: ["User TCC.db exists=true path=/tmp/fake/TCC.db"],
            probeMethod: "test"
        )

        let ledger = ArtifactLedger()
        await ledger.recordStatePaths(state)
        let paths = Set(await ledger.allRecords().map(\.path))
        XCTAssertTrue(paths.contains("/tmp/LaunchAgents/x.plist"))
        XCTAssertTrue(paths.contains("/tmp/.ssh/id_rsa"))
        XCTAssertFalse(paths.contains("/tmp/nope"))
        XCTAssertTrue(paths.contains("/usr/bin/osascript"))
        XCTAssertTrue(paths.contains("/tmp/fake/TCC.db"))
        XCTAssertTrue(paths.contains { $0.hasSuffix("com.apple.TCC/TCC.db") })
    }

    func testAssessPipelineReportJSONAndMarkdown() async throws {
        let result = await AssessPipeline.run(profile: .standard)
        let state = result.state
        let findings = result.findings
        XCTAssertFalse(findings.isEmpty)

        let jsonData = try ReportWriter.render(format: .json, findings: findings, state: state)
        let decoded = try JSONDecoder().decode([Finding].self, from: jsonData)
        XCTAssertEqual(decoded.count, findings.count)
        XCTAssertTrue(decoded.contains { $0.category == .host })

        let mdData = try ReportWriter.render(format: .markdown, findings: findings, state: state)
        let md = String(data: mdData, encoding: .utf8) ?? ""
        XCTAssertTrue(md.contains("Findings") || md.contains("findings") || md.contains("##"), md)
        XCTAssertTrue(
            md.localizedCaseInsensitiveContains("host")
                || md.contains(state.host?.hostname ?? "___none___"),
            "markdown missing host content"
        )

        let sarif = try ReportWriter.render(format: .sarif, findings: findings, state: state)
        let sarifObj = try JSONSerialization.jsonObject(with: sarif) as? [String: Any]
        XCTAssertEqual(sarifObj?["version"] as? String, "2.1.0")
    }

    func testProtectionsSeverityWhenDisabled() async throws {
        var state = CollectedState()
        state.protections = ProtectionsState(
            sipEnabled: false,
            gatekeeperEnabled: true,
            fileVaultOn: true,
            notes: ["test"]
        )
        let findings = try await ProtectionsPostureCheck().evaluate(state: state, context: .assess())
        XCTAssertEqual(findings.first?.severity, .low)
        XCTAssertEqual(findings.first?.id, ProtectionsPostureCheck.id)
    }

    func testInjectSurfaceHighOnDangerousEntitlements() async throws {
        var state = CollectedState()
        state.injectabilityHits = [
            InjectabilityHit(
                path: "/tmp/debug.app",
                hardenedRuntime: false,
                getTaskAllow: true,
                disableLibraryValidation: true,
                riskFlags: ["hardened_runtime_off", "get-task-allow", "disable-library-validation"]
            ),
        ]
        let findings = try await CodesignInjectSurfaceCheck().evaluate(
            state: state,
            context: .assess()
        )
        XCTAssertEqual(findings.first?.severity, .high)
    }
}
