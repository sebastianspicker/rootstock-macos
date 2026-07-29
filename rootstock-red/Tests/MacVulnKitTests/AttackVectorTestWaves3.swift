import XCTest
import RootstockCore
import MacEnumKit
import MacArtifactKit
@testable import MacVulnKit

extension AttackVectorTests {
    func testWave11VectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave11: [String] = [
            URLSchemeHandlerVector.id,
            LaunchdOverrideDepthVector.id,
            BrowserExtensionDualUseVector.id,
            ShortcutsAppIntentsVector.id,
            URLSchemeRemoteCompoundVector.id,
            LaunchdSecurityDisableCompoundVector.id,
            BrowserExtensionCollectionCompoundVector.id,
            ShortcutsLateralCompoundVector.id,
        ]
        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave11.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }
        let firedIds = Set(fired.map(\.id))
        for id in wave11 {
            XCTAssertTrue(firedIds.contains(id), "wave-11 vector must fire: \(id); got \(firedIds.sorted())")
        }
        XCTAssertEqual(firedIds.count, wave11.count, "expected all \(wave11.count) wave-11 vectors; got \(firedIds.sorted())")
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty, "\(f.id) evidence")
            XCTAssertFalse(f.attackTechniques.isEmpty, "\(f.id) ATT&CK")
            XCTAssertTrue(!f.remediation.isEmpty || (f.falsePositiveNotes?.isEmpty == false), "\(f.id) rem/FP")
            XCTAssertTrue(f.dryRunSafe)
            let blob = (f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()).lowercased()
            XCTAssertFalse(blob.contains("password="), "\(f.id) must not dump secrets")
            XCTAssertFalse(blob.contains("register malicious scheme"), "\(f.id) must not register schemes")
            XCTAssertFalse(blob.contains("disable santa now"), "\(f.id) must not disable security")
            XCTAssertFalse(blob.contains("run shortcuts payload"), "\(f.id) must not run shortcuts")
        }
    }

    func testWave11ClusterEmitsRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let ctx = EvaluationContext.assess()
        let cluster = try await Wave11MultiPlaneClusterCheck().evaluate(state: state, context: ctx)
        XCTAssertFalse(cluster.isEmpty, "wave-11 multi-plane cluster should fire on multi-plane synthetic state")
        for f in cluster {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
            XCTAssertTrue(f.id.contains("wave11") || f.id.contains(Wave11MultiPlaneClusterCheck.id))
            let planeEv = f.evidence.first { $0.type == "planes" }
            XCTAssertNotNil(planeEv, "\(f.id) should include planes evidence")
            XCTAssertTrue(planeEv!.detail.contains("count="), "\(f.id) planes evidence should include count")
            XCTAssertTrue(
                planeEv!.detail.contains("url_scheme_handler")
                    || planeEv!.detail.contains("launchd_override_depth")
                    || planeEv!.detail.contains("browser_extension_dualuse")
                    || planeEv!.detail.contains("shortcuts_app_intents"),
                "\(f.id) should rank real Wave-11 surface planes: \(planeEv!.detail)"
            )
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(Wave11MultiPlaneClusterCheck.id))
    }



    func testWave12VectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave12: [String] = [
            WeblocInetlocDeliveryVector.id,
            WeblocRemoteCompoundVector.id,
            MailRulesAutomationVector.id,
            MailRulesScriptCompoundVector.id,
            UnifiedLogObservationVector.id,
            UnifiedLogSensorCompoundVector.id,
            DockPersistenceSurfaceVector.id,
            DockRemoteCompoundVector.id,
            OsascriptScptDeliveryVector.id,
            OsascriptRemoteCompoundVector.id,
            NetworkShareMountVector.id,
            NetworkShareRemoteCompoundVector.id
        ]
        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave12.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }
        let firedIds = Set(fired.map(\.id))
        for id in wave12 {
            XCTAssertTrue(firedIds.contains(id), "wave-12 vector must fire: \(id); got \(firedIds.sorted())")
        }
        XCTAssertEqual(firedIds.count, wave12.count, "expected all \(wave12.count) wave-12 vectors; got \(firedIds.sorted())")
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty, "\(f.id) evidence")
            XCTAssertFalse(f.attackTechniques.isEmpty, "\(f.id) ATT&CK")
            XCTAssertTrue(f.dryRunSafe)
            let blob = (f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()).lowercased()
            XCTAssertFalse(blob.contains("password="), "\(f.id) must not dump secrets")
            XCTAssertFalse(blob.contains("auto-exploit chain payload"), "\(f.id) not weaponized")
        }
    }

    func testWave12ClusterEmitsRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let ctx = EvaluationContext.assess()
        let cluster = try await Wave12MultiPlaneClusterCheck().evaluate(state: state, context: ctx)
        XCTAssertFalse(cluster.isEmpty, "wave-12 multi-plane cluster should fire")
        for f in cluster {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
            let planeEv = f.evidence.first { $0.type == "planes" }
            XCTAssertNotNil(planeEv)
            XCTAssertTrue(planeEv!.detail.contains("count="))
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(Wave12MultiPlaneClusterCheck.id))
    }



    func testWave13VectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave13: [String] = [
            CalendarRemindersAutomationVector.id,
            CalendarRemoteCompoundVector.id,
            GatekeeperAssessmentHistoryVector.id,
            GatekeeperAssessmentRemoteCompoundVector.id,
            HomebrewPackageDualUseVector.id,
            HomebrewRemoteCompoundVector.id,
            CupsPrintDualUseVector.id,
            CupsRemoteCompoundVector.id,
            ScreenCapturePrivacyDualUseVector.id,
            ScreenCaptureFdaCompoundVector.id
        ]
        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave13.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }
        let firedIds = Set(fired.map(\.id))
        for id in wave13 {
            XCTAssertTrue(firedIds.contains(id), "wave-13 vector must fire: \(id); got \(firedIds.sorted())")
        }
        XCTAssertEqual(firedIds.count, wave13.count)
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
            let blob = (f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()).lowercased()
            XCTAssertFalse(blob.contains("password="))
            XCTAssertFalse(blob.contains("auto-exploit chain payload"))
        }
    }

    func testWave13ClusterEmitsRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let ctx = EvaluationContext.assess()
        let cluster = try await Wave13MultiPlaneClusterCheck().evaluate(state: state, context: ctx)
        XCTAssertFalse(cluster.isEmpty, "wave-13 multi-plane cluster should fire")
        for f in cluster {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
            let planeEv = f.evidence.first { $0.type == "planes" }
            XCTAssertNotNil(planeEv)
            XCTAssertTrue(planeEv!.detail.contains("count="))
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(Wave13MultiPlaneClusterCheck.id))
    }



    func testWave14VectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave14: [String] = [
            AutomatorWorkflowVector.id,
            AutomatorWorkflowRemoteCompoundVector.id,
            IcloudDrivePathVector.id,
            IcloudDrivePathRemoteCompoundVector.id,
            BluetoothContinuityDepthVector.id,
            BluetoothContinuityDepthRemoteCompoundVector.id,
            FontValidationDualuseVector.id,
            FontValidationDualuseRemoteCompoundVector.id,
            QuicklookCacheDepthVector.id,
            QuicklookCacheDepthRemoteCompoundVector.id,
            DnsResolverDualuseVector.id,
            DnsResolverDualuseRemoteCompoundVector.id,
            LsQuarantineDbDepthVector.id,
            LsQuarantineDbDepthRemoteCompoundVector.id,
            PamAuthModuleVector.id,
            PamAuthModuleRemoteCompoundVector.id,
            CronAtJobDepthVector.id,
            CronAtJobDepthRemoteCompoundVector.id,
            NotesMetadataPlaneVector.id,
            NotesMetadataPlaneRemoteCompoundVector.id
        ]
        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave14.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }
        let firedIds = Set(fired.map(\.id))
        for id in wave14 {
            XCTAssertTrue(firedIds.contains(id), "wave-14 vector must fire: \(id); got \(firedIds.sorted())")
        }
        XCTAssertEqual(firedIds.count, wave14.count)
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
            let blob = (f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()).lowercased()
            XCTAssertFalse(blob.contains("password="))
            XCTAssertFalse(blob.contains("auto-exploit chain payload"))
        }
    }

    func testWave14ClusterEmitsRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let ctx = EvaluationContext.assess()
        let cluster = try await Wave14MultiPlaneClusterCheck().evaluate(state: state, context: ctx)
        XCTAssertFalse(cluster.isEmpty, "wave-14 multi-plane cluster should fire")
        for f in cluster {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
            let planeEv = f.evidence.first { $0.type == "planes" }
            XCTAssertNotNil(planeEv)
            XCTAssertTrue(planeEv!.detail.contains("count="))
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(Wave14MultiPlaneClusterCheck.id))
    }



    func testWave15VectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave15: [String] = [
            PhotosLibraryPathVector.id,
            PhotosLibraryPathRemoteCompoundVector.id,
            VpnConfigDualuseVector.id,
            VpnConfigDualuseRemoteCompoundVector.id,
            SandboxContainerDepthVector.id,
            SandboxContainerDepthRemoteCompoundVector.id,
            XpcMachServiceDepthVector.id,
            XpcMachServiceDepthRemoteCompoundVector.id,
            TmLocalSnapshotDepthVector.id,
            TmLocalSnapshotDepthRemoteCompoundVector.id,
            EmondLegacyDepthVector.id,
            EmondLegacyDepthRemoteCompoundVector.id,
            ScreenSharingArdDepthVector.id,
            ScreenSharingArdDepthRemoteCompoundVector.id,
            KeychainAclPathVector.id,
            KeychainAclPathRemoteCompoundVector.id,
            PythonRuntimeDualuseVector.id,
            PythonRuntimeDualuseRemoteCompoundVector.id,
            ShellPluginManagerVector.id,
            ShellPluginManagerRemoteCompoundVector.id
        ]
        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave15.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }
        let firedIds = Set(fired.map(\.id))
        for id in wave15 {
            XCTAssertTrue(firedIds.contains(id), "wave-15 vector must fire: \(id); got \(firedIds.sorted())")
        }
        XCTAssertEqual(firedIds.count, wave15.count)
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
            let blob = (f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()).lowercased()
            XCTAssertFalse(blob.contains("password="))
            XCTAssertFalse(blob.contains("auto-exploit chain payload"))
        }
    }

    func testWave15ClusterEmitsRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let ctx = EvaluationContext.assess()
        let cluster = try await Wave15MultiPlaneClusterCheck().evaluate(state: state, context: ctx)
        XCTAssertFalse(cluster.isEmpty, "wave-15 multi-plane cluster should fire")
        for f in cluster {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
            let planeEv = f.evidence.first { $0.type == "planes" }
            XCTAssertNotNil(planeEv)
            XCTAssertTrue(planeEv!.detail.contains("count="))
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(Wave15MultiPlaneClusterCheck.id))
    }



    func testWave16VectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave16 = Array(AttackVectorTestFixtures.requiredVectorIDs.suffix(50))
        var fired: [Finding] = []

        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave16.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }

        assertWave16Vectors(fired, expected: wave16)
    }

    private func assertWave16Vectors(_ findings: [Finding], expected: [String]) {
        let findingIDs = Set(findings.map(\.id))
        for id in expected {
            XCTAssertTrue(findingIDs.contains(id), "wave-16 vector must fire: \(id)")
        }
        XCTAssertEqual(findingIDs.count, expected.count)
        for finding in findings {
            XCTAssertFalse(finding.evidence.isEmpty)
            XCTAssertTrue(finding.dryRunSafe)
            XCTAssertFalse((finding.title + finding.evidence.map(\.detail).joined()).lowercased().contains("password="))
        }
    }

    func testWave16ClusterEmitsRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let cluster = try await Wave16MultiPlaneClusterCheck().evaluate(state: state, context: EvaluationContext.assess())
        XCTAssertFalse(cluster.isEmpty)
        for f in cluster {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
            XCTAssertNotNil(f.evidence.first { $0.type == "planes" })
        }
        XCTAssertTrue(Set(VulnModuleRegistry.allChecks().map { type(of: $0).id }).contains(Wave16MultiPlaneClusterCheck.id))
    }
}
