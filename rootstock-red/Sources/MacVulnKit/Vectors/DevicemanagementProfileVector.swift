import Foundation
import RootstockCore

/// Path-to-impact: Device management profile residual depth.
public struct DevicemanagementProfileVector: Check {
    public static let id = "rootstock.vector.mdm.devicemanagement_profile"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.devicemanagementProfile
        let a = s?.profilesToolPaths.count ?? 0
        let b = s?.managedPrefPaths.count ?? 0
        let c = s?.mdmClientPaths.count ?? 0
        let surface = s?.deviceMgmtSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.devicemanagement_profile"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "devicemanagement_profile_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.profilesToolPaths + s.managedPrefPaths + s.mdmClientPaths, type: "devicemanagement_profile_path", detail: "Device management profile path", limit: 10)
            evidence += VectorEvidence.notes(s.notes, type: "devicemanagement_profile_note", limit: 4)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never installs configuration profiles or enrolls hosts in MDM."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Device management profile with remote amplifier" : "Device management profile residual depth", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1484", "T1072", "T1562"], remediation: [
                "Inventory and baseline Device management profile paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never installs configuration profiles or enrolls hosts in MDM",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
