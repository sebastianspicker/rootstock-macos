import Foundation
import RootstockCore

/// Path-to-impact: weakened SIP / Gatekeeper / FileVault, or unknown posture under elevated context.
public struct ProtectionsWeakVector: Check {
    public static let id = "rootstock.vector.privesc.protections_weak"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let posture = Self.posture(from: state)
        guard posture.shouldEmit else { return [] }
        return [Self.finding(for: posture)]
    }

    private struct DisabledProtection { let name: String; let technique: String }
    private struct ProtectionState { let name: String; let enabled: Bool?; let technique: String }
    private struct Posture {
        let disabled: [DisabledProtection]
        let allUnknown: Bool
        let otherMisconfig: Bool
        let evidence: [Evidence]
        var shouldEmit: Bool { !disabled.isEmpty || (allUnknown && otherMisconfig) }
    }

    private static func posture(from state: CollectedState) -> Posture {
        let protections = state.protections
        let sip = protections?.sipEnabled
        let gatekeeper = protections?.gatekeeperEnabled
        let fileVault = protections?.fileVaultOn
        let disabled = disabledProtections(sip: sip, gatekeeper: gatekeeper, fileVault: fileVault)
        let otherMisconfig = hasOtherMisconfiguration(in: state)
        var evidence = protections?.notes.prefix(10).map { Evidence(type: "note", detail: $0) } ?? []
        evidence += [Evidence(type: "sip", detail: "sipEnabled=\(sip.rootstockDescribe)"), Evidence(type: "gatekeeper", detail: "gatekeeperEnabled=\(gatekeeper.rootstockDescribe)"), Evidence(type: "filevault", detail: "fileVaultOn=\(fileVault.rootstockDescribe)")]
        if state.host?.isRoot == true { evidence.append(Evidence(type: "context", detail: "process isRoot=true - elevated assess context")) }
        if otherMisconfig && disabled.isEmpty { evidence.append(Evidence(type: "path_to_impact", detail: "Protections unknown/uncollected while other misconfig signals exist (inject surface, weak dylibs, remote access, or root context)")) }
        return Posture(disabled: disabled, allUnknown: sip == nil && gatekeeper == nil && fileVault == nil, otherMisconfig: otherMisconfig, evidence: evidence)
    }

    private static func disabledProtections(sip: Bool?, gatekeeper: Bool?, fileVault: Bool?) -> [DisabledProtection] {
        [ProtectionState(name: "SIP", enabled: sip, technique: "T1562.001"), ProtectionState(name: "Gatekeeper", enabled: gatekeeper, technique: "T1553.001"), ProtectionState(name: "FileVault", enabled: fileVault, technique: "T1552")].compactMap { $0.enabled == false ? DisabledProtection(name: $0.name, technique: $0.technique) : nil }
    }

    private static func hasOtherMisconfiguration(in state: CollectedState) -> Bool {
        state.host?.isRoot == true || state.injectabilityHits.contains { !$0.riskFlags.isEmpty } || !state.dylibRiskHits.filter({ !$0.weakDylibs.isEmpty }).isEmpty || state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
    }

    private static func finding(for posture: Posture) -> Finding {
        let sipDisabled = posture.disabled.contains { $0.name == "SIP" }
        let title = sipDisabled ? "Privilege-escalation surface: SIP disabled (high impact)" : posture.disabled.isEmpty ? "Protections posture unknown with supporting path-to-impact signals" : "Protections weak: \(posture.disabled.map(\.name).joined(separator: ", ")) disabled"
        var techniques = Set(["T1082", "T1562.001"])
        posture.disabled.forEach { techniques.insert($0.technique) }
        if sipDisabled { techniques.insert("T1548") }
        return Finding(id: Self.id, title: title, severity: sipDisabled ? .high : posture.disabled.isEmpty ? .low : .medium, category: .misconfig, resolution: .init(evidence: posture.evidence, attackTechniques: techniques.sorted(), remediation: ["Re-enable SIP (csrutil), Gatekeeper (spctl), and FileVault via MDM/compliance", "Treat disabled SIP as high-priority host integrity failure", "OPSEC: assessing protections via csrutil/spctl may itself be logged - prefer MDM inventory"], falsePositiveNotes: posture.disabled.isEmpty ? "Unknown is not proof of disabled protections; corroborate with admin tooling" : "Verify disabled flags with privileged host tooling before remediating"), runtime: .init(confidence: posture.disabled.isEmpty ? .low : .medium, dryRunSafe: true, opsecScore: 18, esfExpected: ["OPEN"]))
    }

}
