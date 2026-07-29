import XCTest
import RootstockCore
import MacEnumKit
import MacArtifactKit
@testable import MacVulnKit

extension AttackVectorTests {
    func testSyntheticStateFiresAtLeastThreeVectors() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)

        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let results = try await check.evaluate(state: state, context: context)
            fired.append(contentsOf: results)
        }

        let vectorIds = Set(fired.map(\.id)).intersection(Set(AttackVectorPlane.ids))
        XCTAssertGreaterThanOrEqual(
            vectorIds.count,
            3,
            "expected ≥3 vector ids on synthetic state; got \(vectorIds.sorted()) findings=\(fired.map(\.id))"
        )

        // Known weak synthetic inputs should hit these specifically.
        XCTAssertTrue(
            vectorIds.contains(ProtectionsWeakVector.id),
            "protections_weak should fire (SIP false)"
        )
        XCTAssertTrue(
            vectorIds.contains(InjectSurfaceVector.id),
            "inject.surface should fire (get-task-allow / HR off)"
        )
        XCTAssertTrue(
            vectorIds.contains(CredOrIdentityPivotVector.id),
            "cred_or_identity_pivot should fire (cred paths + adBound)"
        )
        XCTAssertTrue(
            vectorIds.contains(LOLExecutionChainVector.id),
            "lool.execution_chain should fire (osascript+launchctl)"
        )

        for f in fired {
            XCTAssertTrue(f.dryRunSafe, "\(f.id) dryRunSafe")
            XCTAssertFalse(f.evidence.isEmpty, "\(f.id) missing evidence")
            XCTAssertFalse(f.attackTechniques.isEmpty, "\(f.id) missing ATT&CK")
            XCTAssertFalse(f.remediation.isEmpty, "\(f.id) missing remediation")
            XCTAssertNotNil(f.opsecScore, "\(f.id) missing opsecScore")
        }

        // BTM honesty on persist vector.
        if let persist = fired.first(where: { $0.id == UserWritableLaunchAgentsVector.id }) {
            let blob = (persist.evidence.map(\.detail) + persist.remediation).joined(separator: " ")
            XCTAssertTrue(
                blob.localizedCaseInsensitiveContains("BTM")
                    || blob.localizedCaseInsensitiveContains("Background Task"),
                "persist vector should mention BTM honesty"
            )
            XCTAssertGreaterThanOrEqual(persist.opsecScore ?? 0, 50, "silent claim OPSEC should be high")
        }
    }

    func testExpandedVectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let newIds: [String] = [
            TCCFDAPermissionPivotVector.id,
            PrivilegedHelperSygextVector.id,
            MDMManagementGapVector.id,
            BrowserSessionArtifactPivotVector.id,
            WritablePrivilegedPathsVector.id,
        ]

        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard newIds.contains(id) else { continue }
            let results = try await check.evaluate(state: state, context: context)
            fired.append(contentsOf: results)
        }

        let firedIds = Set(fired.map(\.id))
        XCTAssertGreaterThanOrEqual(
            firedIds.count,
            4,
            "expected ≥4 new vectors on synthetic state; got \(firedIds.sorted())"
        )
        for id in newIds where firedIds.contains(id) {
            let f = fired.first { $0.id == id }!
            XCTAssertFalse(f.evidence.isEmpty, "\(id) evidence")
            XCTAssertFalse(f.attackTechniques.isEmpty, "\(id) ATT&CK")
            let hasRemediationOrFP = !f.remediation.isEmpty || (f.falsePositiveNotes?.isEmpty == false)
            XCTAssertTrue(hasRemediationOrFP, "\(id) remediation or FP notes")
            XCTAssertNotNil(f.opsecScore, "\(id) opsecScore")
            XCTAssertTrue(f.dryRunSafe, "\(id) dryRunSafe")
        }

        // PEASS-class writable path vector must fire via collector note / temp path.
        XCTAssertTrue(
            firedIds.contains(WritablePrivilegedPathsVector.id),
            "writable_privileged_paths should fire on synthetic privesc notes"
        )
        XCTAssertTrue(
            firedIds.contains(TCCFDAPermissionPivotVector.id),
            "fda_permission_pivot should fire (FDA true + sensitive paths)"
        )
        XCTAssertTrue(
            firedIds.contains(BrowserSessionArtifactPivotVector.id),
            "browser session pivot should fire"
        )
    }

    func testPrivescClusterEmitsRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let findings = try await PrivescPathClusterCheck().evaluate(
            state: state,
            context: .assess()
        )
        XCTAssertFalse(findings.isEmpty, "privesc cluster should emit on synthetic weak state")
        for f in findings {
            XCTAssertTrue(f.id.hasPrefix(PrivescPathClusterCheck.id) || f.id == PrivescPathClusterCheck.id
                || f.id.contains("privesc"), "unexpected id \(f.id)")
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
        }
        // Registry surfaces the cluster check.
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(PrivescPathClusterCheck.id))
    }

    func testSOTA2026VectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave2: [String] = [
            XPCHelperAbuseSurfaceVector.id,
            PlatformSSOLateralVector.id,
            SecurityProductGapVector.id,
            SystemLaunchDaemonSurfaceVector.id,
            SMAppLoginItemHonestyVector.id,
        ]

        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave2.contains(id) else { continue }
            let results = try await check.evaluate(state: state, context: context)
            fired.append(contentsOf: results)
        }

        let firedIds = Set(fired.map(\.id))
        XCTAssertGreaterThanOrEqual(
            firedIds.count,
            3,
            "expected ≥3 2026 coverage vectors; got \(firedIds.sorted())"
        )
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty, "\(f.id) evidence")
            XCTAssertFalse(f.attackTechniques.isEmpty, "\(f.id) ATT&CK")
            let hasRemediationOrFP = !f.remediation.isEmpty || (f.falsePositiveNotes?.isEmpty == false)
            XCTAssertTrue(hasRemediationOrFP, "\(f.id) remediation or FP")
            XCTAssertNotNil(f.opsecScore, "\(f.id) opsec")
            XCTAssertTrue(f.dryRunSafe, "\(f.id) dryRunSafe")
        }
    }

    func testIdentityEDRClusterEmitsRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let findings = try await IdentityEDRClusterCheck().evaluate(
            state: state,
            context: .assess()
        )
        XCTAssertFalse(findings.isEmpty, "identity/EDR cluster should emit on synthetic state")
        for f in findings {
            XCTAssertTrue(
                f.id.hasPrefix(IdentityEDRClusterCheck.id),
                "unexpected cluster finding id \(f.id)"
            )
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(IdentityEDRClusterCheck.id))
    }

    func testWave4VectorsFireOnSyntheticState() async throws {
        var state = Self.syntheticWeakState()
        // Tailor for wave-4 path-to-impact (non-duplicative of prior waves).
        state.collectorNotes["codesign.quarantine_hits"] = "/tmp/rootstock-red-q/quarantined.app"
        state.collectorNotes["auth.keychain_paths"] = "/tmp/rootstock-red-kc/login.keychain-db"
        state.collectorNotes["tcc.screen_accessibility"] = "screen_recording=likely|accessibility=unknown"
        state.mdm = MDMState( enrolled: true, vendorHints: ["Jamf"], managedPreferenceNames: ["com.jamf.management"], profileStoreReadable: true, profileFileCount: 3, pppcPolicyPresent: true, notes: ["synthetic enrolled Jamf channel"] )
        state.loobins = state.loobins + [
            LOOBinHit(name: "security", path: "/usr/bin/security", present: true, tactics: ["credential-access", "discovery"]),
            LOOBinHit(name: "codesign", path: "/usr/bin/codesign", present: true, tactics: ["discovery"]),
            LOOBinHit(name: "spctl", path: "/usr/sbin/spctl", present: true, tactics: ["discovery"]),
            LOOBinHit(name: "screencapture", path: "/usr/sbin/screencapture", present: true, tactics: ["collection"]),
        ]
        let context = EvaluationContext.assess(profile: .standard)
        let wave4: [String] = [
            QuarantineXattrSurfaceVector.id,
            KeychainPathSurfaceVector.id,
            MDMManagementChannelSurfaceVector.id,
            ScreenAccessibilitySurfaceVector.id,
            SecurityCLIDualUseVector.id,
        ]
        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave4.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }
        let firedIds = Set(fired.map(\.id))
        XCTAssertGreaterThanOrEqual( firedIds.count, 3, "expected ≥3 wave-4 vectors; got \(firedIds.sorted())" )
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty, "\(f.id) evidence")
            XCTAssertFalse(f.attackTechniques.isEmpty, "\(f.id) ATT&CK")
            XCTAssertTrue(!f.remediation.isEmpty || (f.falsePositiveNotes?.isEmpty == false), "\(f.id) rem/FP")
            XCTAssertNotNil(f.opsecScore)
            XCTAssertTrue(f.dryRunSafe)
            // Never claim secret dump
            let blob = (f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()).lowercased()
            XCTAssertFalse(blob.contains("password="), "\(f.id) must not dump secrets")
        }
        XCTAssertTrue(firedIds.contains(QuarantineXattrSurfaceVector.id) || firedIds.contains(KeychainPathSurfaceVector.id))
    }

    func testDeliveryTrustClusterEmitsRankedFindings() async throws {
        var state = Self.syntheticWeakState()
        state.collectorNotes["codesign.quarantine_hits"] = "/tmp/q.app"
        // GK already false + SSH true in syntheticWeakState → gatekeeper_off_with_remote rule
        let findings = try await DeliveryTrustClusterCheck().evaluate(state: state, context: .assess())
        XCTAssertFalse(findings.isEmpty, "delivery trust cluster should emit")
        for f in findings {
            XCTAssertTrue(f.id.hasPrefix(DeliveryTrustClusterCheck.id), "id \(f.id)")
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(DeliveryTrustClusterCheck.id))
    }

    func testWave5VectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave5: [String] = [
            ESFSensorGapVector.id,
            CVEPatchDebtSuggesterVector.id,
            TCCPermissionGraphDepthVector.id,
            XPCClientValidationSurfaceVector.id,
            LaunchConstraintInjectTruthVector.id,
            LOOBinDualUseMultiStageVector.id,
        ]
        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave5.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }
        let firedIds = Set(fired.map(\.id))
        XCTAssertGreaterThanOrEqual(
            firedIds.count,
            4,
            "expected ≥4 wave-5 vectors; got \(firedIds.sorted())"
        )
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty, "\(f.id) evidence")
            XCTAssertFalse(f.attackTechniques.isEmpty, "\(f.id) ATT&CK")
            XCTAssertTrue(!f.remediation.isEmpty || (f.falsePositiveNotes?.isEmpty == false), "\(f.id) rem/FP")
            XCTAssertNotNil(f.opsecScore)
            XCTAssertTrue(f.dryRunSafe)
            let blob = (f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()).lowercased()
            XCTAssertFalse(blob.contains("password="), "\(f.id) must not dump secrets")
        }
    }

    func testWave5ClustersEmitRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let ctx = EvaluationContext.assess()
        let esf = try await ESFEDRPostureClusterCheck().evaluate(state: state, context: ctx)
        let cve = try await CVEPatchDebtClusterCheck().evaluate(state: state, context: ctx)
        let tcc = try await TCCGraphClusterCheck().evaluate(state: state, context: ctx)
        XCTAssertFalse(esf.isEmpty || cve.isEmpty || tcc.isEmpty,
                       "wave-5 clusters should emit; esf=\(esf.count) cve=\(cve.count) tcc=\(tcc.count)")
        for f in esf + cve + tcc {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(ESFEDRPostureClusterCheck.id))
        XCTAssertTrue(registered.contains(CVEPatchDebtClusterCheck.id))
        XCTAssertTrue(registered.contains(TCCGraphClusterCheck.id))
    }

    func testWave6VectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave6: [String] = [
            NetworkExtensionFilterGapVector.id,
            AuthRightsPrivilegeSurfaceVector.id,
            DeveloperToolchainDualUseVector.id,
            TimeMachineSnapshotAccessVector.id,
            MobileconfigSideloadRiskVector.id,
        ]
        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave6.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }
        let firedIds = Set(fired.map(\.id))
        XCTAssertGreaterThanOrEqual(
            firedIds.count,
            4,
            "expected ≥4 wave-6 vectors; got \(firedIds.sorted())"
        )
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty, "\(f.id) evidence")
            XCTAssertFalse(f.attackTechniques.isEmpty, "\(f.id) ATT&CK")
            XCTAssertTrue(!f.remediation.isEmpty || (f.falsePositiveNotes?.isEmpty == false), "\(f.id) rem/FP")
            XCTAssertNotNil(f.opsecScore)
            XCTAssertTrue(f.dryRunSafe)
            let blob = (f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()).lowercased()
            XCTAssertFalse(blob.contains("password="), "\(f.id) must not dump secrets")
        }
    }

    func testWave6ClustersEmitRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let ctx = EvaluationContext.assess()
        let ne = try await NetworkExtensionClusterCheck().evaluate(state: state, context: ctx)
        let authDev = try await AuthDevPrivilegeClusterCheck().evaluate(state: state, context: ctx)
        let data = try await DataAccessSurfaceClusterCheck().evaluate(state: state, context: ctx)
        XCTAssertFalse(
            ne.isEmpty || authDev.isEmpty || data.isEmpty,
            "wave-6 clusters should emit; ne=\(ne.count) authDev=\(authDev.count) data=\(data.count)"
        )
        for f in ne + authDev + data {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(NetworkExtensionClusterCheck.id))
        XCTAssertTrue(registered.contains(AuthDevPrivilegeClusterCheck.id))
        XCTAssertTrue(registered.contains(DataAccessSurfaceClusterCheck.id))
    }
}
