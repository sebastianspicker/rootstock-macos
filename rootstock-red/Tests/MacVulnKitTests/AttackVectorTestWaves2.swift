import XCTest
import RootstockCore
import MacEnumKit
import MacArtifactKit
@testable import MacVulnKit

extension AttackVectorTests {
    func testWave9ClusterSilentWhenSurfacesEmptyDespiteCollectorNotes() async throws {
        var state = CollectedState()
        state.packageKitInstallerDesign = PackageKitInstallerDesignState( installerServicePaths: [], receiptAndHistoryPaths: [], installerPluginPaths: [], toolingPaths: [], designSurfacePresent: false, notes: ["collector ran - no installer design surface"] )
        state.archiveQuarantineExtractor = ArchiveQuarantineExtractorState( thirdPartyExtractorPaths: [], stockExtractorPaths: [], archiveDropHints: [], extractorSurfacePresent: false, notes: ["collector ran - no extractor surface"] )
        state.infoStealerPathPlane = InfoStealerPathPlaneState( browserAdjacentPaths: [], messagingAndVaultPaths: [], walletAndSyncPaths: [], collectionSurfacePresent: false, notes: ["collector ran - no stealer path surface"] )
        state.tccEsfVisibilityDepth = TCCESFVisibilityDepthState( tccDbPathHits: [], visibilityToolPaths: [], privacyPrefPaths: [], visibilityDepth: "thin", visibilitySurfacePresent: false, notes: ["collector ran - no visibility surface"] )
        state.mdmProfileParseDepth = MDMProfileParseDepthState( examinedProfilePaths: [], payloadTypes: [], parsedProfileCount: 0, displayNamePresent: false, parseSurfacePresent: false, notes: ["collector ran - no parse surface"] )
        state.collectorNotes["collect.packagekit_installer_design"] = "surface=false"
        state.collectorNotes["collect.archive_quarantine_extractor"] = "surface=false"
        state.collectorNotes["collect.infostealer_path_plane"] = "surface=false"
        state.collectorNotes["collect.tcc_esf_visibility_depth"] = "surface=false"
        state.collectorNotes["collect.mdm_profile_parse_depth"] = "surface=false"
        state.network = NetworkState(reachability: .init(remoteLoginSSH: false, screenSharingARD: false), notes: ["hardened remote off"])
        state.tcc = TCCState(fullDiskAccessLikely: false, notes: ["no FDA"], probeMethod: "synthetic")
        state.esf = nil

        let ctx = EvaluationContext.assess(); let cluster = try await Wave9InstallerCollectionClusterCheck().evaluate(state: state, context: ctx)
        XCTAssertTrue( cluster.isEmpty, "cluster must stay silent when collectors ran but Wave-9 surfaces empty; got \(cluster.map(\.id))" )
    }

    /// Stock pf/ALF-only inventory + remote/high-value MUST fire NE filter gap.
    /// Stock `/etc/pf.conf` must never suppress enterprise content-filter gap findings.
    func testNEFilterGapFiresWhenOnlyStockPfPresent() async throws {
        var state = CollectedState()
        // Simulate collector after stock/enterprise split: notes mention pf, but
        // contentFilterHints stay empty (enterprise only) and neApps empty.
        state.networkExtension = NetworkExtensionState( frameworkPresent: true, vpnConfigPaths: [], contentFilterHints: [], packetTunnelHints: [], neAppPaths: [], notes: [ "stock_os_network: pf_conf path=/etc/pf.conf", "stock_os_network: pf_anchors path=/etc/pf.anchors", "stock_os_network: application_firewall_alf path=/Library/Preferences/com.apple.alf.plist", "enterprise content-filter none", ] )
        state.network = NetworkState(reachability: .init(remoteLoginSSH: true, screenSharingARD: false)); state.identity = IdentityState(adBound: true, platformSSO: false)
        state.credPaths = [
            CredPathHit(kind: "ssh", path: NSHomeDirectory() + "/.ssh/id_rsa", exists: true),
        ]
        state.collectorNotes["collect.network_extension"] =
            "framework=true vpnConfigs=0 contentFilter=0 packetTunnel=0 neApps=0 stockNetworkArtifacts=3"
        state.collectorNotes["ne.filter_gap"] =
            "enterprise_content_filter=0 neApps=0 stock_os_network=3"

        let gap = try await NetworkExtensionFilterGapVector().evaluate( state: state, context: .assess() )
        XCTAssertEqual(gap.count, 1, "NE filter gap must fire for stock-pf-only + remote"); XCTAssertEqual(gap.first?.id, NetworkExtensionFilterGapVector.id)
        XCTAssertFalse(gap.first?.evidence.isEmpty ?? true)

        let cluster = try await NetworkExtensionClusterCheck().evaluate( state: state, context: .assess() )
        let thinRemote = cluster.first { $0.id.hasSuffix("no_filter_with_remote") }
        XCTAssertNotNil( thinRemote, "cluster no_filter_with_remote must fire; got \(cluster.map(\.id))" )

        // Negative: enterprise filter hint present should suppress thin gap (no remote-only fire // if filters non-zero). Build state with enterprise filter + still remote.
        var withEnterprise = state
        withEnterprise.networkExtension = NetworkExtensionState( frameworkPresent: true, vpnConfigPaths: [], contentFilterHints: [ "content_filter_prefs:/Library/Preferences/com.apple.networkextension.filter.plist", ], packetTunnelHints: [], neAppPaths: ["/Applications/LuLu.app"], notes: ["enterprise filter present"] )
        withEnterprise.collectorNotes.removeValue(forKey: "ne.filter_gap")
        let suppressed = try await NetworkExtensionFilterGapVector().evaluate( state: withEnterprise, context: .assess() )
        XCTAssertTrue( suppressed.isEmpty, "enterprise filter + neApp must suppress thin filter gap; got \(suppressed.map(\.id))" )

        // Even if stock hints leaked into contentFilterHints, defensive filter must still fire gap.
        var leakedStock = state
        leakedStock.networkExtension = NetworkExtensionState( frameworkPresent: true, contentFilterHints: [ "pf_conf:/etc/pf.conf", "application_firewall:/Library/Preferences/com.apple.alf.plist", ], neAppPaths: [], notes: ["leaked stock only"] )
        let stillGap = try await NetworkExtensionFilterGapVector().evaluate( state: leakedStock, context: .assess() )
        XCTAssertEqual( stillGap.count, 1, "stock pf/ALF leaked into contentFilterHints must still fire gap after defensive filter" )
    }

    /// Honest fixture: Apple-only ES inventory (endpointsecurityd/framework in notes,
    /// empty third-party clientPaths) + remote/high-value MUST still fire sensor-gap.
    /// Stock OS paths must not suppress third-party sensor gap.
    func testESFSensorGapFiresWhenOnlyAppleInfrastructurePresent() async throws {
        var state = CollectedState()
        // Simulate collector output after the Apple-infra split: notes mention apple paths,
        // but clientPaths/edrHints stay empty (third-party only).
        state.esf = ESFPostureState(
            frameworkPresent: true,
            clientPaths: [],
            systemExtensionCount: 0,
            edrHints: [],
            notes: [
                "apple_infra: endpointsecurityd path=/usr/libexec/endpointsecurityd",
                "apple_infra: EndpointSecurity.framework path=/System/Library/Frameworks/EndpointSecurity.framework",
                "systemExtension root present (directory existence ≠ EDR client)",
                "third_party_clients none",
            ]
        )
        state.securityProducts = [
            SecurityProductHit(name: "SyntheticEDR", path: "/Applications/SyntheticEDR.app", present: false),
        ]
        state.network = NetworkState(reachability: .init(remoteLoginSSH: true, screenSharingARD: false))
        state.identity = IdentityState(adBound: true, platformSSO: false)
        state.collectorNotes["collect.esf_endpoint_security"] =
            "framework=true thirdPartyClients=0 thirdPartySysext≈0 edrHints=0 appleInfra=2"
        state.collectorNotes["esf.sensor_gap"] = "third_party_clients=0 apple_infra_only=true"

        let gap = try await ESFSensorGapVector().evaluate(state: state, context: .assess())
        XCTAssertEqual(gap.count, 1, "sensor gap must fire for Apple-infra-only + remote")
        XCTAssertEqual(gap.first?.id, ESFSensorGapVector.id)
        XCTAssertFalse(gap.first?.evidence.isEmpty ?? true)
        let evidenceBlob = gap.first?.evidence.map(\.detail).joined(separator: " ") ?? ""
        XCTAssertTrue(
            evidenceBlob.contains("thirdParty") || evidenceBlob.contains("third-party")
                || evidenceBlob.localizedCaseInsensitiveContains("Apple"),
            "evidence should distinguish third-party vs Apple infra"
        )

        let cluster = try await ESFEDRPostureClusterCheck().evaluate(state: state, context: .assess())
        let thinRemote = cluster.first { $0.id.hasSuffix("thin_sensor_remote") }
        XCTAssertNotNil(thinRemote, "cluster thin_sensor_remote must fire; got \(cluster.map(\.id))")

        // Negative: third-party client present → gap should NOT fire.
        var withClient = state
        withClient.esf = ESFPostureState(
            frameworkPresent: true,
            clientPaths: ["/Library/CS/falconctl"],
            systemExtensionCount: 0,
            edrHints: ["CrowdStrike Falcon"],
            notes: ["third_party_client: CrowdStrike"]
        )
        withClient.collectorNotes.removeValue(forKey: "esf.sensor_gap")
        let noGap = try await ESFSensorGapVector().evaluate(state: withClient, context: .assess())
        XCTAssertTrue(noGap.isEmpty, "third-party client must suppress sensor-gap")
    }

    /// Live collector → vector: after real collect, if no third-party clients and remote is
    /// synthetic-injected, sensor-gap semantics still hold (Apple paths in notes only).
    func testESFCollectorToVectorAppleInfraDoesNotSuppressGap() async throws {
        let collected = try await ESFEndpointSecurityCollector().collect(context: .assess())
        // Assert collector semantics first.
        for path in collected.esf?.clientPaths ?? [] {
            XCTAssertFalse(
                path.contains("endpointsecurityd") || path == "/Library/SystemExtensions",
                "live collector leaked Apple path into clients: \(path)"
            )
        }

        var state = collected
        // Inject remote + empty products so path-to-impact compounds apply.
        if state.securityProducts.contains(where: \.present) {
            // Host has real EDR - vector correctly silent; still assert collector split.
            XCTAssertTrue(true, "host has third-party product paths; skip gap fire assertion")
            return
        }
        state.network = NetworkState(reachability: .init(remoteLoginSSH: true))
        state.securityProducts = state.securityProducts.map {
            SecurityProductHit(name: $0.name, path: $0.path, present: false)
        }
        // If collector already found third-party clients, gap must not fire.
        if !(state.esf?.clientPaths.isEmpty ?? true) || !(state.esf?.edrHints.isEmpty ?? true) {
            let findings = try await ESFSensorGapVector().evaluate(state: state, context: .assess())
            XCTAssertTrue(
                findings.isEmpty,
                "third-party clients present - gap must not fire; clients=\(state.esf?.clientPaths ?? [])"
            )
            return
        }
        let findings = try await ESFSensorGapVector().evaluate(state: state, context: .assess())
        XCTAssertEqual(
            findings.count,
            1,
            "Apple-infra-only live collect + remote must fire sensor-gap; note=\(state.collectorNotes)"
        )
        XCTAssertEqual(findings.first?.id, ESFSensorGapVector.id)
    }

    func testWave3VectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave3: [String] = [
            SudoersMisconfigSurfaceVector.id,
            PeriodicMaintenanceSurfaceVector.id,
            GatekeeperTrustGapVector.id,
            AutomationExecutionSurfaceVector.id,
            ElectronDevtoolsSurfaceVector.id,
        ]
        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave3.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }
        let firedIds = Set(fired.map(\.id))
        XCTAssertGreaterThanOrEqual(
            firedIds.count,
            3,
            "expected ≥3 wave-3 vectors; got \(firedIds.sorted())"
        )
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty, "\(f.id) evidence")
            XCTAssertFalse(f.attackTechniques.isEmpty, "\(f.id) ATT&CK")
            XCTAssertTrue(!f.remediation.isEmpty || (f.falsePositiveNotes?.isEmpty == false), "\(f.id) rem/FP")
            XCTAssertNotNil(f.opsecScore, "\(f.id) opsec")
            XCTAssertTrue(f.dryRunSafe)
        }
    }

    func testTrustChainClusterEmitsRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let findings = try await TrustChainClusterCheck().evaluate(state: state, context: .assess())
        XCTAssertFalse(findings.isEmpty, "trust chain cluster should emit")
        for f in findings {
            XCTAssertTrue(f.id.hasPrefix(TrustChainClusterCheck.id), "id \(f.id)")
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(TrustChainClusterCheck.id))
    }

    func testProtectionsWeakHighWhenSIPDisabled() async throws {
        var state = CollectedState()
        state.protections = ProtectionsState(
            sipEnabled: false,
            gatekeeperEnabled: true,
            fileVaultOn: true
        )
        let findings = try await ProtectionsWeakVector().evaluate(state: state, context: .assess())
        XCTAssertEqual(findings.count, 1)
        XCTAssertEqual(findings.first?.severity, .high)
        XCTAssertEqual(findings.first?.category, .misconfig)
    }

    func testProtectionsWeakLowWhenUnknownWithRoot() async throws {
        var state = CollectedState()
        state.protections = ProtectionsState(
            sipEnabled: nil,
            gatekeeperEnabled: nil,
            fileVaultOn: nil,
            notes: ["unknown"]
        )
        state.host = HostState(
            hostname: "h",
            username: "root",
            osVersion: "14.0",
            arch: "arm64",
            processArch: "arm64",
            isRoot: true
        )
        let findings = try await ProtectionsWeakVector().evaluate(state: state, context: .assess())
        XCTAssertEqual(findings.first?.severity, .low)
        XCTAssertEqual(findings.first?.id, ProtectionsWeakVector.id)
    }

    func testProtectionsWeakSilentWhenHardened() async throws {
        var state = CollectedState()
        state.protections = ProtectionsState(
            sipEnabled: true,
            gatekeeperEnabled: true,
            fileVaultOn: true
        )
        let findings = try await ProtectionsWeakVector().evaluate(state: state, context: .assess())
        XCTAssertTrue(findings.isEmpty)
    }

    func testRemoteAccessSurfaceWhenSSHEnabled() async throws {
        var state = CollectedState()
        state.network = NetworkState(reachability: .init(remoteLoginSSH: true, screenSharingARD: false), artifacts: .init(remoteLoginPlistPresent: true, sshdConfigPresent: true))
        let findings = try await RemoteAccessSurfaceVector().evaluate(state: state, context: .assess())
        XCTAssertEqual(findings.first?.id, RemoteAccessSurfaceVector.id)
        XCTAssertEqual(findings.first?.severity, .medium)
        XCTAssertEqual(findings.first?.category, .network)
        XCTAssertTrue(findings.first?.attackTechniques.contains("T1021.004") == true)
    }

    func testCredPivotNeverClaimsSecretDump() async throws {
        var state = CollectedState()
        state.credPaths = [
            CredPathHit(kind: "ssh", path: "/Users/t/.ssh/id_rsa", exists: true),
        ]
        let findings = try await CredOrIdentityPivotVector().evaluate(state: state, context: .assess())
        let text = findings.map { f in
            f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()
        }.joined()
        XCTAssertFalse(text.localizedCaseInsensitiveContains("password="))
        XCTAssertFalse(text.localizedCaseInsensitiveContains("private key material"))
        XCTAssertTrue(text.localizedCaseInsensitiveContains("metadata") || text.localizedCaseInsensitiveContains("path"))
    }

    // MARK: - Pipeline integration

    func testAssessPipelineRegistersAndMayFireVectors() async {
        // Ensure vectors are in the live registry used by the pipeline.
        let registryIds = Set(VulnModuleRegistry.fullRegistry().checkIds)
        for id in AttackVectorPlane.ids {
            XCTAssertTrue(registryIds.contains(id), "pipeline registry missing \(id)")
        }

        let findings = await AssessPipeline.run(profile: .standard).findings
        let hostVectorIds = Set(findings.map(\.id)).intersection(Set(AttackVectorPlane.ids))

        if hostVectorIds.count >= 3 {
            XCTAssertGreaterThanOrEqual(hostVectorIds.count, 3)
            return
        }

        // Hardened / minimal hosts may not fire 3 vectors - synthetic fallback for reliability.
        let synthetic = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        var syntheticFindings: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            if let results = try? await check.evaluate(state: synthetic, context: context) {
                syntheticFindings.append(contentsOf: results)
            }
        }
        let syntheticIds = Set(syntheticFindings.map(\.id)).intersection(Set(AttackVectorPlane.ids))
        XCTAssertGreaterThanOrEqual(
            syntheticIds.count,
            3,
            "host fired \(hostVectorIds.count) vectors; synthetic fallback expected ≥3, got \(syntheticIds.sorted())"
        )
    }
}
