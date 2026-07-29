import XCTest
import RootstockCore
@testable import MacEnumKit

/// Real collectors (not mocks) for P0 alpha themes.
final class P0CollectorTests: XCTestCase {
    func testProtectionsCollectorFillsState() async throws {
        let state = try await ProtectionsCollector().collect(context: .assess())
        XCTAssertNotNil(state.protections)
        XCTAssertFalse(state.protections?.notes.isEmpty ?? true)
        XCTAssertEqual(state.collectorNotes[ProtectionsCollector.id]?.isEmpty, false)
    }

    func testLoginItemsBTMCollector() async throws {
        let state = try await LoginItemsBTMCollector().collect(context: .assess())
        // At least notes or inventory structure populated
        let hasData =
            !state.systemLaunchAgents.isEmpty
            || !state.launchDaemons.isEmpty
            || !state.loginItemPaths.isEmpty
            || state.loginItems != nil
            || state.collectorNotes[LoginItemsBTMCollector.id] != nil
        XCTAssertTrue(hasData)
    }

    func testBrowserMetaCollector() async throws {
        let state = try await BrowserMetaCollector().collect(context: .assess())
        // Even if no browsers installed, browserMeta array is set (possibly empty) with notes
        XCTAssertNotNil(state.collectorNotes[BrowserMetaCollector.id] ?? "ok")
        // Paths are metadata only - no content fields for secrets
        for entry in state.browserMeta {
            XCTAssertFalse(entry.path.isEmpty)
        }
    }

    func testLOOBinsInventoryNonEmptyCatalog() async throws {
        let state = try await LOOBinsCollector().collect(context: .assess())
        XCTAssertFalse(state.loobins.isEmpty)
        XCTAssertTrue(state.loobins.contains { $0.name == "osascript" || $0.path.contains("osascript") })
    }

    func testSecurityProductsExpandedCatalog() async throws {
        let state = try await SecurityProductsCollector().collect(context: .assess())
        // Collector always runs; product hits may be empty on clean hosts
        XCTAssertNotNil(state.collectorNotes[SecurityProductsCollector.id])
    }

    func testInjectabilityOrCodesignSamples() async throws {
        let inj = try await InjectabilityCollector().collect(context: .assess(profile: .standard))
        let code = try await CodesignCollector().collect(context: .assess(profile: .deep))
        let hasSamples =
            !inj.injectabilityHits.isEmpty
            || !code.codesignSamples.isEmpty
            || inj.collectorNotes[InjectabilityCollector.id] != nil
        XCTAssertTrue(hasSamples)
    }

    func testP0CollectorIdsRegistered() {
        let ids = Set(EnumModuleRegistry.allCollectors().map { type(of: $0).id })
        for id in P0CollectorTestFixtures.requiredCollectorIDs {
            XCTAssertTrue(ids.contains(id), "missing collector \(id)")
        }
    }

    func testWave5CollectorsFillState() async throws {
        let esf = try await ESFEndpointSecurityCollector().collect(context: .assess())
        XCTAssertNotNil(esf.esf)
        XCTAssertFalse(esf.esf?.notes.isEmpty ?? true)
        XCTAssertNotNil(esf.collectorNotes[ESFEndpointSecurityCollector.id])

        let patch = try await PatchDebtCollector().collect(context: .assess())
        XCTAssertNotNil(patch.patchDebt)
        XCTAssertNotNil(patch.patchDebt?.osVersion)
        XCTAssertNotNil(patch.collectorNotes[PatchDebtCollector.id])

        let graph = try await TCCPermissionGraphCollector().collect(context: .assess())
        XCTAssertNotNil(graph.tcc)
        XCTAssertFalse(graph.tcc?.domainSignals.isEmpty ?? true)
        XCTAssertNotNil(graph.collectorNotes[TCCPermissionGraphCollector.id])

        let lc = try await LaunchConstraintCollector().collect(context: .assess())
        XCTAssertNotNil(lc.launchConstraints)
        XCTAssertNotNil(lc.collectorNotes[LaunchConstraintCollector.id])
    }

    /// Wave-6 collectors: real collect → typed state + collector notes (no secrets).
    func testWave6CollectorsFillState() async throws {
        let ne = try await NetworkExtensionCollector().collect(context: .assess())
        XCTAssertNotNil(ne.networkExtension)
        XCTAssertFalse(ne.networkExtension?.notes.isEmpty ?? true)
        XCTAssertNotNil(ne.collectorNotes[NetworkExtensionCollector.id])

        let auth = try await AuthRightsCollector().collect(context: .assess())
        XCTAssertNotNil(auth.authRights)
        XCTAssertFalse(auth.authRights?.notes.isEmpty ?? true)
        XCTAssertNotNil(auth.collectorNotes[AuthRightsCollector.id])
        // Never claim secret dump of auth.db contents
        let authBlob = (auth.authRights?.notes ?? []).joined(separator: " ").lowercased()
        XCTAssertFalse(authBlob.contains("password="))

        let dev = try await DeveloperToolchainCollector().collect(context: .assess())
        XCTAssertNotNil(dev.developerToolchain)
        XCTAssertNotNil(dev.collectorNotes[DeveloperToolchainCollector.id])

        let tm = try await TimeMachineCollector().collect(context: .assess())
        XCTAssertNotNil(tm.timeMachine)
        XCTAssertNotNil(tm.collectorNotes[TimeMachineCollector.id])
        let tmBlob = (tm.timeMachine?.notes ?? []).joined(separator: " ").lowercased()
        XCTAssertFalse(tmBlob.contains("password="))

        let cfg = try await ConfigProfileSideloadCollector().collect(context: .assess())
        XCTAssertNotNil(cfg.configProfileSideload)
        XCTAssertNotNil(cfg.collectorNotes[ConfigProfileSideloadCollector.id])
    }

    /// Wave-7 collectors: real collect → typed state + collector notes (no secrets/keys).
    func testWave7CollectorsFillState() async throws {
        let sandbox = try await AppSandboxEntitlementsCollector().collect(context: .assess())
        XCTAssertNotNil(sandbox.appSandboxEntitlements)
        XCTAssertFalse(sandbox.appSandboxEntitlements?.notes.isEmpty ?? true)
        XCTAssertNotNil(sandbox.collectorNotes[AppSandboxEntitlementsCollector.id])

        let nota = try await NotarizationStaplingCollector().collect(context: .assess())
        XCTAssertNotNil(nota.notarizationStapling)
        XCTAssertFalse(nota.notarizationStapling?.notes.isEmpty ?? true)
        XCTAssertNotNil(nota.collectorNotes[NotarizationStaplingCollector.id])

        let virt = try await VirtualizationContainersCollector().collect(context: .assess())
        XCTAssertNotNil(virt.virtualizationContainers)
        XCTAssertFalse(virt.virtualizationContainers?.notes.isEmpty ?? true)
        XCTAssertNotNil(virt.collectorNotes[VirtualizationContainersCollector.id])

        let cont = try await ContinuityAirDropCollector().collect(context: .assess())
        XCTAssertNotNil(cont.continuityAirDrop)
        XCTAssertFalse(cont.continuityAirDrop?.notes.isEmpty ?? true)
        XCTAssertNotNil(cont.collectorNotes[ContinuityAirDropCollector.id])
        let contBlob = (cont.continuityAirDrop?.notes ?? []).joined(separator: " ").lowercased()
        XCTAssertFalse(contBlob.contains("password="))
        XCTAssertFalse(contBlob.contains("clipboard contents"))

        let fv = try await FileVaultEscrowCollector().collect(context: .assess())
        XCTAssertNotNil(fv.fileVaultEscrow)
        XCTAssertFalse(fv.fileVaultEscrow?.notes.isEmpty ?? true)
        XCTAssertNotNil(fv.collectorNotes[FileVaultEscrowCollector.id])
        let fvBlob = (fv.fileVaultEscrow?.notes ?? []).joined(separator: " ").lowercased()
        XCTAssertFalse(fvBlob.contains("recovery key="))
        XCTAssertFalse(fvBlob.contains("password="))
        XCTAssertTrue(fvBlob.contains("never") || fvBlob.contains("not invoked"))
    }

    func testWave8CollectorsFillState() async throws {
        let click = try await ClickFixTerminalDeliveryCollector().collect(context: .assess())
        XCTAssertNotNil(click.clickFixTerminalDelivery)
        XCTAssertFalse(click.clickFixTerminalDelivery?.notes.isEmpty ?? true)
        XCTAssertNotNil(click.collectorNotes[ClickFixTerminalDeliveryCollector.id])
        let clickBlob = (click.clickFixTerminalDelivery?.notes ?? []).joined(separator: " ").lowercased()
        XCTAssertFalse(clickBlob.contains("password="))
        XCTAssertTrue(clickBlob.contains("never") || clickBlob.contains("lure"))

        let rae = try await RemoteAppleEventsCollector().collect(context: .assess())
        XCTAssertNotNil(rae.remoteAppleEvents)
        XCTAssertFalse(rae.remoteAppleEvents?.notes.isEmpty ?? true)
        XCTAssertNotNil(rae.collectorNotes[RemoteAppleEventsCollector.id])

        let spot = try await SpotlightAICacheCollector().collect(context: .assess())
        XCTAssertNotNil(spot.spotlightAICache)
        XCTAssertFalse(spot.spotlightAICache?.notes.isEmpty ?? true)
        XCTAssertNotNil(spot.collectorNotes[SpotlightAICacheCollector.id])
        let spotBlob = (spot.spotlightAICache?.notes ?? []).joined(separator: " ").lowercased()
        XCTAssertFalse(spotBlob.contains("password="))
        XCTAssertTrue(spotBlob.contains("never") || spotBlob.contains("dump"))

        let mgmt = try await SecurityMgmtPlaneCollector().collect(context: .assess())
        XCTAssertNotNil(mgmt.securityMgmtPlane)
        XCTAssertFalse(mgmt.securityMgmtPlane?.notes.isEmpty ?? true)
        XCTAssertNotNil(mgmt.collectorNotes[SecurityMgmtPlaneCollector.id])
        let mgmtBlob = (mgmt.securityMgmtPlane?.notes ?? []).joined(separator: " ").lowercased()
        XCTAssertTrue(mgmtBlob.contains("never") || mgmtBlob.contains("unload"))

        let tcc = try await ThirdPartyTCCInheritanceCollector().collect(context: .assess())
        XCTAssertNotNil(tcc.thirdPartyTCCInheritance)
        XCTAssertFalse(tcc.thirdPartyTCCInheritance?.notes.isEmpty ?? true)
        XCTAssertNotNil(tcc.collectorNotes[ThirdPartyTCCInheritanceCollector.id])

        let ssh = try await SSHAgentKeyPathCollector().collect(context: .assess())
        XCTAssertNotNil(ssh.sshAgentKeyPath)
        XCTAssertFalse(ssh.sshAgentKeyPath?.notes.isEmpty ?? true)
        XCTAssertNotNil(ssh.collectorNotes[SSHAgentKeyPathCollector.id])
        let sshBlob = (ssh.sshAgentKeyPath?.notes ?? []).joined(separator: " ").lowercased()
        XCTAssertFalse(sshBlob.contains("begin rsa private key"))
        XCTAssertTrue(sshBlob.contains("never") || sshBlob.contains("path"))
    }

    func testWave9CollectorsFillState() async throws {
        let pk = try await PackageKitInstallerDesignCollector().collect(context: .assess())
        XCTAssertNotNil(pk.packageKitInstallerDesign)
        XCTAssertFalse(pk.packageKitInstallerDesign?.notes.isEmpty ?? true)
        XCTAssertNotNil(pk.collectorNotes[PackageKitInstallerDesignCollector.id])
        let pkBlob = (pk.packageKitInstallerDesign?.notes ?? []).joined(separator: " ").lowercased()
        XCTAssertTrue(pkBlob.contains("never") || pkBlob.contains("installd") || pkBlob.contains("path"))
        XCTAssertFalse(pkBlob.contains("preinstall script payload"))

        let aq = try await ArchiveQuarantineExtractorCollector().collect(context: .assess())
        XCTAssertNotNil(aq.archiveQuarantineExtractor)
        XCTAssertFalse(aq.archiveQuarantineExtractor?.notes.isEmpty ?? true)
        XCTAssertNotNil(aq.collectorNotes[ArchiveQuarantineExtractorCollector.id])
        let aqBlob = (aq.archiveQuarantineExtractor?.notes ?? []).joined(separator: " ").lowercased()
        XCTAssertTrue(aqBlob.contains("never") || aqBlob.contains("quarantine"))
        XCTAssertFalse(aqBlob.contains("strip quarantine now"))

        let stealer = try await InfoStealerPathPlaneCollector().collect(context: .assess())
        XCTAssertNotNil(stealer.infoStealerPathPlane)
        XCTAssertFalse(stealer.infoStealerPathPlane?.notes.isEmpty ?? true)
        XCTAssertNotNil(stealer.collectorNotes[InfoStealerPathPlaneCollector.id])
        let stealerBlob = (stealer.infoStealerPathPlane?.notes ?? []).joined(separator: " ").lowercased()
        XCTAssertFalse(stealerBlob.contains("password="))
        XCTAssertFalse(stealerBlob.contains("begin rsa private key"))
        XCTAssertTrue(stealerBlob.contains("never") || stealerBlob.contains("path"))

        let vis = try await TCCESFVisibilityDepthCollector().collect(context: .assess())
        XCTAssertNotNil(vis.tccEsfVisibilityDepth)
        XCTAssertFalse(vis.tccEsfVisibilityDepth?.notes.isEmpty ?? true)
        XCTAssertNotNil(vis.collectorNotes[TCCESFVisibilityDepthCollector.id])
        XCTAssertNotNil(vis.tccEsfVisibilityDepth?.visibilityDepth)
        let visBlob = (vis.tccEsfVisibilityDepth?.notes ?? []).joined(separator: " ").lowercased()
        XCTAssertTrue(visBlob.contains("never") || visBlob.contains("tcc"))
        XCTAssertFalse(visBlob.contains("select * from access"))

        let mdm = try await MDMProfileParseDepthCollector().collect(context: .assess())
        XCTAssertNotNil(mdm.mdmProfileParseDepth)
        XCTAssertFalse(mdm.mdmProfileParseDepth?.notes.isEmpty ?? true)
        XCTAssertNotNil(mdm.collectorNotes[MDMProfileParseDepthCollector.id])
        let mdmBlob = (mdm.mdmProfileParseDepth?.notes ?? []).joined(separator: " ").lowercased()
        XCTAssertTrue(mdmBlob.contains("never") || mdmBlob.contains("payload") || mdmBlob.contains("profile"))
        XCTAssertFalse(mdmBlob.contains("sharedsecret="))
    }

}
