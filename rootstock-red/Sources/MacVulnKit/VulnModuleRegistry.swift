/// Assess check registry: host/posture checks + multi-plane vector plane + Wave clusters.
/// Consumed by `rootstock-red audit` and `list checks|vectors`.
import Foundation
import RootstockCore
import MacEnumKit

/// Default assess checks for RootstockRed.
public enum VulnModuleRegistry {
    public static func allChecks() -> [any Check] {
        [
            HostIdentityCheck(),
            LaunchAgentsPresentCheck(),
            SystemLaunchdInventoryCheck(),
            SecurityToolsDetectedCheck(),
            TCCPreflightCheck(),
            CredPathsCheck(),
            MDMHintsCheck(),
            MDMProfilesCheck(),
            IdentityPostureCheck(),
            LOOBinInventoryCheck(),
            LOLPlannerCheck(),
            ProtectionsPostureCheck(),
            BTMLoginItemsCheck(),
            BrowserMetaPathsCheck(),
            CodesignInjectSurfaceCheck(),
            NetworkSharingPostureCheck(),
            // PEASS-class privesc / misconfig rule cluster (API-first over CollectedState).
            PrivescPathClusterCheck(),
            // Identity × EDR × remote posture cluster (coverage gap-driven).
            IdentityEDRClusterCheck(),
            // Trust-chain cluster: Gatekeeper × codesign × get-task-allow.
            TrustChainClusterCheck(),
            // Delivery-trust cluster: quarantine × XProtect inventory × GK+remote compound.
            DeliveryTrustClusterCheck(),
            // 2026 coverage clusters.
            ESFEDRPostureClusterCheck(),
            CVEPatchDebtClusterCheck(),
            TCCGraphClusterCheck(),
            // NE/filter, auth×dev privilege, TM/mobileconfig data access.
            NetworkExtensionClusterCheck(),
            AuthDevPrivilegeClusterCheck(),
            DataAccessSurfaceClusterCheck(),
            // trust-delivery depth, local data protection, kill-chain compounds.
            TrustDeliveryDepthClusterCheck(),
            LocalDataProtectionClusterCheck(),
            KillChainCompoundClusterCheck(),
            // delivery × lateral multi-plane compound.
            Wave8DeliveryLateralClusterCheck(),
            // installer × collection × visibility compound.
            Wave9InstallerCollectionClusterCheck(),
            // Residual pair cluster: installer × extractor × stealer × visibility compounds.
            Wave10ResidualPairClusterCheck(),
            // Multi-plane cluster: URL handlers × launchd overrides × browser extensions × Shortcuts.
            Wave11MultiPlaneClusterCheck(),
            // Multi-plane cluster (6 net-new themes beyond prior coverage).
            Wave12MultiPlaneClusterCheck(),
            // Multi-plane cluster (5 net-new themes beyond prior coverage).
            Wave13MultiPlaneClusterCheck(),
            // Multi-plane cluster (10 net-new themes beyond prior coverage).
            Wave14MultiPlaneClusterCheck(),
            // Multi-plane cluster (10 net-new themes beyond prior coverage).
            Wave15MultiPlaneClusterCheck(),
            // Multi-plane cluster (25 themes / 50 red|blue half-pairs).
            Wave16MultiPlaneClusterCheck(),
        ] + AttackVectorPlane.allChecks()
    }

    public static func fullRegistry() -> ModuleRegistry {
        EnumModuleRegistry.defaultRegistry(checks: allChecks())
    }
}

/// Complete assess pipeline for tests and embedders (no CLI).
public struct AssessPipelineResult: Sendable {
    public let state: CollectedState
    public let findings: [Finding]
    public let ledger: ArtifactLedger

    public init(state: CollectedState, findings: [Finding], ledger: ArtifactLedger) {
        self.state = state
        self.findings = findings
        self.ledger = ledger
    }
}

public enum AssessPipeline {
    /// Run collectors → checks → OPSEC annotation for the given profile.
    ///
    /// - Parameters:
    ///   - profile: Scan cost/profile.
    ///   - ledger: Optional artifact ledger; when nil a fresh ledger is created.
    ///   - projectDirectory: When set, writes `artifacts.json` under this directory after collection.
    /// - Returns: Collected state, annotated findings, and the ledger used (with state paths recorded).
    @discardableResult
    public static func run(
        profile: ScanProfile = .standard,
        ledger: ArtifactLedger? = nil,
        projectDirectory: URL? = nil
    ) async -> AssessPipelineResult {
        let context = EvaluationContext.assess(
            profile: profile,
            projectDirectory: projectDirectory
        )
        let registry = VulnModuleRegistry.fullRegistry()
        let state = await CollectionRunner.run(registry: registry, context: context)
        var findings = await CheckRunner.run(registry: registry, state: state, context: context)
        findings = OpsecScorer().annotateAll(findings)

        let activeLedger = ledger ?? ArtifactLedger()
        await activeLedger.recordStatePaths(state)

        if let projectDirectory {
            let artifactsURL = projectDirectory.appendingPathComponent("artifacts.json")
            try? await activeLedger.write(to: artifactsURL)
        }

        return AssessPipelineResult(state: state, findings: findings, ledger: activeLedger)
    }
}
