import XCTest
import RootstockCore
import MacEnumKit
import MacArtifactKit
@testable import MacVulnKit

extension AttackVectorTests {
    func testWave7VectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave7: [String] = [
            SandboxEntitlementThickClientVector.id,
            NotarizationStaplingGapVector.id,
            VirtContainerDualUseVector.id,
            ContinuityAirDropSurfaceVector.id,
            FileVaultEscrowPostureVector.id,
        ]
        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave7.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }
        let firedIds = Set(fired.map(\.id))
        XCTAssertGreaterThanOrEqual(
            firedIds.count,
            4,
            "expected ≥4 wave-7 vectors; got \(firedIds.sorted())"
        )
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty, "\(f.id) evidence")
            XCTAssertFalse(f.attackTechniques.isEmpty, "\(f.id) ATT&CK")
            XCTAssertTrue(!f.remediation.isEmpty || (f.falsePositiveNotes?.isEmpty == false), "\(f.id) rem/FP")
            XCTAssertNotNil(f.opsecScore)
            XCTAssertTrue(f.dryRunSafe)
            let blob = (f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()).lowercased()
            XCTAssertFalse(blob.contains("password="), "\(f.id) must not dump secrets")
            XCTAssertFalse(blob.contains("recovery key="), "\(f.id) must not dump recovery keys")
        }
    }

    func testWave7ClustersEmitRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let ctx = EvaluationContext.assess()
        let trust = try await TrustDeliveryDepthClusterCheck().evaluate(state: state, context: ctx)
        let local = try await LocalDataProtectionClusterCheck().evaluate(state: state, context: ctx)
        let kill = try await KillChainCompoundClusterCheck().evaluate(state: state, context: ctx)
        XCTAssertFalse(
            trust.isEmpty && local.isEmpty && kill.isEmpty,
            "wave-7 clusters should emit; trust=\(trust.count) local=\(local.count) kill=\(kill.count)"
        )
        XCTAssertFalse(kill.isEmpty, "kill-chain compound should fire on multi-plane synthetic state")
        for f in trust + local + kill {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(TrustDeliveryDepthClusterCheck.id))
        XCTAssertTrue(registered.contains(LocalDataProtectionClusterCheck.id))
        XCTAssertTrue(registered.contains(KillChainCompoundClusterCheck.id))
    }

    func testWave8VectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave8: [String] = [
            ClickFixTerminalDeliveryVector.id,
            RemoteAppleEventsLateralVector.id,
            SpotlightAICacheAccessVector.id,
            SecurityMgmtPlaneSurfaceVector.id,
            ThirdPartyTCCInheritanceVector.id,
            SSHAgentKeyPathLateralVector.id,
        ]
        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave8.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }
        let firedIds = Set(fired.map(\.id))
        // Every Wave-8 vector family must fire on the intentional weak synthetic state.
        for id in wave8 {
            XCTAssertTrue(firedIds.contains(id), "wave-8 vector family must fire: \(id); got \(firedIds.sorted())")
        }
        XCTAssertEqual(firedIds.count, wave8.count, "expected all \(wave8.count) wave-8 vectors; got \(firedIds.sorted())")
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty, "\(f.id) evidence")
            XCTAssertFalse(f.attackTechniques.isEmpty, "\(f.id) ATT&CK")
            XCTAssertTrue(!f.remediation.isEmpty || (f.falsePositiveNotes?.isEmpty == false), "\(f.id) rem/FP")
            XCTAssertNotNil(f.opsecScore)
            XCTAssertTrue(f.dryRunSafe)
            let blob = (f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()).lowercased()
            XCTAssertFalse(blob.contains("password="), "\(f.id) must not dump secrets")
            XCTAssertFalse(blob.contains("begin rsa private key"), "\(f.id) must not dump keys")
            XCTAssertFalse(blob.contains("paste this payload"), "\(f.id) must not deliver ClickFix recipes")
            XCTAssertFalse(blob.contains("unload edr now"), "\(f.id) must not weaponize unload")
        }
    }

    func testWave8ClusterEmitsRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let ctx = EvaluationContext.assess()
        let cluster = try await Wave8DeliveryLateralClusterCheck().evaluate(state: state, context: ctx)
        XCTAssertFalse(cluster.isEmpty, "wave-8 delivery×lateral cluster should fire on multi-plane synthetic state")
        for f in cluster {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
            XCTAssertTrue(f.id.contains("wave8") || f.id.contains(Wave8DeliveryLateralClusterCheck.id))
            let planeEv = f.evidence.first { $0.type == "planes" }
            XCTAssertNotNil(planeEv, "\(f.id) should include planes evidence")
            XCTAssertTrue(planeEv!.detail.contains("count="), "\(f.id) planes evidence should include count")
            // Synthetic weak state co-presents real Wave-8 surfaces (not notes alone).
            XCTAssertTrue(
                planeEv!.detail.contains("clickfix_delivery")
                    || planeEv!.detail.contains("ssh_key_depth")
                    || planeEv!.detail.contains("rae_lateral"),
                "\(f.id) should rank real Wave-8 surface planes: \(planeEv!.detail)"
            )
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(Wave8DeliveryLateralClusterCheck.id))
    }

    func testWave8ClusterSilentWhenSurfacesEmptyDespiteCollectorNotes() async throws {
        var state = CollectedState()
        state.clickFixTerminalDelivery = ClickFixTerminalDeliveryState( terminalAppPaths: [], scriptEditorPaths: [], loaderBinaryPaths: [], pasteWarningHints: [], deliverySurfacePresent: false, notes: ["collector ran - no delivery surface"] )
        state.remoteAppleEvents = RemoteAppleEventsState( remoteAEPrefPaths: [], eppcFrameworkPaths: [], remoteMgmtHints: [], remoteAutomationSurfacePresent: false, notes: ["collector ran - no RAE surface"] )
        state.spotlightAICache = SpotlightAICacheState( spotlightPaths: [], metadataFrameworkPaths: [], aiCachePathHints: [], dataAccessSurfacePresent: false, notes: ["collector ran - no index surface"] )
        state.securityMgmtPlane = SecurityMgmtPlaneState( managementCLIPaths: [], privilegedHelperPaths: [], unloadAdjacentHints: [], managementPlanePresent: false, notes: ["collector ran - no mgmt surface"] )
        state.thirdPartyTCCInheritance = ThirdPartyTCCInheritanceState( thickClientAppPaths: [], embeddedInterpreterPaths: [], electronHelperPaths: [], inheritanceSurfacePresent: false, notes: ["collector ran - thick=0, no inheritance surface"] )
        state.sshAgentKeyPath = SSHAgentKeyPathState( agentSocketPaths: [], keyPathHits: [], sshdSupportPaths: [], lateralPathSurfacePresent: false, notes: ["collector ran - no key path surface"] )
        // Notes present for all Wave-8 collectors (must not invent planes).
        state.collectorNotes["collect.clickfix_terminal_delivery"] = "surface=false"
        state.collectorNotes["collect.remote_apple_events"] = "surface=false"
        state.collectorNotes["collect.spotlight_ai_cache"] = "surface=false"
        state.collectorNotes["collect.security_mgmt_plane"] = "surface=false"
        state.collectorNotes["collect.third_party_tcc_inheritance"] = "surface=false thick=0"
        state.collectorNotes["collect.ssh_agent_key_path"] = "surface=false"
        state.collectorNotes["collect.esf_endpoint_security"] = "framework=true clients=0"
        // No remote / FDA amplifiers either.
        state.network = NetworkState(reachability: .init(remoteLoginSSH: false, screenSharingARD: false), notes: ["hardened remote off"])
        state.tcc = TCCState(fullDiskAccessLikely: false, notes: ["no FDA"], probeMethod: "synthetic")
        // ESF state absent so sensor_gap is not typed-present either.
        state.esf = nil
        state.securityProducts = [
            SecurityProductHit(name: "PresentEDR", path: "/Applications/PresentEDR.app", present: true),
        ]

        let ctx = EvaluationContext.assess(); let cluster = try await Wave8DeliveryLateralClusterCheck().evaluate(state: state, context: ctx)
        XCTAssertTrue( cluster.isEmpty, "cluster must stay silent when collectors ran but Wave-8 surfaces empty; got \(cluster.map(\.id))" )

        // Matching vectors should also stay silent on empty inheritance (thick=0).
        let tccFindings = try await ThirdPartyTCCInheritanceVector().evaluate(state: state, context: ctx)
        XCTAssertTrue( tccFindings.isEmpty, "third_party_inheritance must not fire when thick=0; got \(tccFindings.map(\.id))" )
    }

    func testWave9VectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave9: [String] = [
            PackageKitInstallerDesignVector.id,
            ArchiveQuarantineExtractorVector.id,
            InfoStealerPathPlaneVector.id,
            TCCESFVisibilityDepthVector.id,
            MDMProfileParseDepthVector.id,
        ]
        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave9.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }
        let firedIds = Set(fired.map(\.id))
        for id in wave9 {
            XCTAssertTrue(firedIds.contains(id), "wave-9 vector family must fire: \(id); got \(firedIds.sorted())")
        }
        XCTAssertEqual(firedIds.count, wave9.count, "expected all \(wave9.count) wave-9 vectors; got \(firedIds.sorted())")
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty, "\(f.id) evidence")
            XCTAssertFalse(f.attackTechniques.isEmpty, "\(f.id) ATT&CK")
            XCTAssertTrue(!f.remediation.isEmpty || (f.falsePositiveNotes?.isEmpty == false), "\(f.id) rem/FP")
            XCTAssertNotNil(f.opsecScore)
            XCTAssertTrue(f.dryRunSafe)
            let blob = (f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()).lowercased()
            XCTAssertFalse(blob.contains("password="), "\(f.id) must not dump secrets")
            XCTAssertFalse(blob.contains("begin rsa private key"), "\(f.id) must not dump keys")
            XCTAssertFalse(blob.contains("strip quarantine now"), "\(f.id) must not weaponize quarantine strip")
            XCTAssertFalse(blob.contains("build malicious pkg"), "\(f.id) must not build pkgs")
            XCTAssertFalse(blob.contains("select * from access"), "\(f.id) must not dump TCC.db")
        }
    }

    func testWave9ClusterEmitsRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let ctx = EvaluationContext.assess()
        let cluster = try await Wave9InstallerCollectionClusterCheck().evaluate(state: state, context: ctx)
        XCTAssertFalse(cluster.isEmpty, "wave-9 installer×collection cluster should fire on multi-plane synthetic state")
        for f in cluster {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
            XCTAssertTrue(f.id.contains("wave9") || f.id.contains(Wave9InstallerCollectionClusterCheck.id))
            let planeEv = f.evidence.first { $0.type == "planes" }
            XCTAssertNotNil(planeEv, "\(f.id) should include planes evidence")
            XCTAssertTrue(planeEv!.detail.contains("count="), "\(f.id) planes evidence should include count")
            XCTAssertTrue(
                planeEv!.detail.contains("installer_design")
                    || planeEv!.detail.contains("stealer_paths")
                    || planeEv!.detail.contains("archive_extractor"),
                "\(f.id) should rank real Wave-9 surface planes: \(planeEv!.detail)"
            )
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(Wave9InstallerCollectionClusterCheck.id))
    }

    func testWave10ResidualPairVectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave10: [String] = [
            PackageKitReceiptScriptCompoundVector.id,
            ExtractorQuarantineCompoundVector.id,
            StealerRemoteCompoundVector.id,
            VisibilitySensorCompoundVector.id,
        ]
        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave10.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }
        let firedIds = Set(fired.map(\.id))
        for id in wave10 {
            XCTAssertTrue(
                firedIds.contains(id),
                "wave-10 residual-pair vector must fire: \(id); got \(firedIds.sorted())"
            )
        }
        XCTAssertEqual(
            firedIds.count,
            wave10.count,
            "expected all \(wave10.count) wave-10 compounds; got \(firedIds.sorted())"
        )
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty, "\(f.id) evidence")
            XCTAssertFalse(f.attackTechniques.isEmpty, "\(f.id) ATT&CK")
            XCTAssertTrue(!f.remediation.isEmpty || (f.falsePositiveNotes?.isEmpty == false), "\(f.id) rem/FP")
            XCTAssertNotNil(f.opsecScore)
            XCTAssertTrue(f.dryRunSafe)
            let blob = (f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()).lowercased()
            XCTAssertFalse(blob.contains("password="), "\(f.id) must not dump secrets")
            XCTAssertFalse(blob.contains("begin rsa private key"), "\(f.id) must not dump keys")
            XCTAssertFalse(blob.contains("strip quarantine now"), "\(f.id) must not weaponize quarantine strip")
            XCTAssertFalse(blob.contains("build malicious pkg"), "\(f.id) must not build pkgs")
            XCTAssertFalse(blob.contains("select * from access"), "\(f.id) must not dump TCC.db")
        }
    }

    func testWave10ResidualPairClusterEmitsRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let ctx = EvaluationContext.assess()
        let cluster = try await Wave10ResidualPairClusterCheck().evaluate(state: state, context: ctx)
        XCTAssertFalse(
            cluster.isEmpty,
            "wave-10 residual-pair cluster should fire when ≥2 pair planes present on synthetic state"
        )
        for f in cluster {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
            XCTAssertTrue(f.id.contains("wave10") || f.id.contains(Wave10ResidualPairClusterCheck.id))
            let planeEv = f.evidence.first { $0.type == "planes" }
            XCTAssertNotNil(planeEv, "\(f.id) should include planes evidence")
            XCTAssertTrue(planeEv!.detail.contains("count="), "\(f.id) planes evidence should include count")
            XCTAssertTrue(
                planeEv!.detail.contains("installer_design")
                    || planeEv!.detail.contains("stealer_paths")
                    || planeEv!.detail.contains("archive_extractor")
                    || planeEv!.detail.contains("visibility_depth"),
                "\(f.id) should rank real residual pair planes: \(planeEv!.detail)"
            )
            let blob = (f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()).lowercased()
            XCTAssertFalse(blob.contains("password="), "\(f.id) must not dump secrets")
            XCTAssertFalse(blob.contains("begin rsa private key"), "\(f.id) must not dump keys")
            XCTAssertFalse(blob.contains("strip quarantine now"), "\(f.id) must not weaponize quarantine strip")
            XCTAssertFalse(blob.contains("build malicious pkg"), "\(f.id) must not build pkgs")
            XCTAssertFalse(blob.contains("select * from access"), "\(f.id) must not dump TCC.db")
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(Wave10ResidualPairClusterCheck.id))
    }
}
