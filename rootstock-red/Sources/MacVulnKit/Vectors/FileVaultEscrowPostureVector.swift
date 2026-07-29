import Foundation
import RootstockCore

/// Path-to-impact: FileVault / recovery escrow posture.
///
/// Research basis: FV status + institutional escrow research.
/// Safety and behavior: path-only escrow honesty; compounds remote access; never dumps recovery keys.
public struct FileVaultEscrowPostureVector: Check {
    public static let id = "rootstock.vector.filevault.escrow_posture"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard Self.hasFileVaultSurface(state), Self.hasPathToImpact(state) else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }


    private static func hasFileVaultSurface(_ state: CollectedState) -> Bool {
        let fv = state.fileVaultEscrow
        let fileVaultOn = fv?.fileVaultOn ?? state.protections?.fileVaultOn
        let note = state.collectorNotes["collect.filevault_escrow"] != nil
            || state.collectorNotes["collect.protections"] != nil
        return fileVaultOn != nil
            || (fv?.escrowPathHints.count ?? 0) > 0
            || (fv?.institutionalEscrowHints.count ?? 0) > 0
            || fv?.fdesetupPresent == true
            || note
    }

    private static func hasPathToImpact(_ state: CollectedState) -> Bool {
        let fv = state.fileVaultEscrow
        return fv?.fileVaultOn ?? state.protections?.fileVaultOn == false
            || remoteAccess(state)
            || state.mdm?.enrolled == false
            || (fv?.escrowPathHints.count ?? 0) > 0
            || (fv?.institutionalEscrowHints.count ?? 0) > 0
            || fv?.fdesetupPresent == true
    }

    private static func remoteAccess(_ state: CollectedState) -> Bool {
        state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
    }


    private func evidence(for state: CollectedState) -> [Evidence] {
        let fv = state.fileVaultEscrow
        let fileVaultOn = fv?.fileVaultOn ?? state.protections?.fileVaultOn
        let escrow = fv?.escrowPathHints.count ?? 0
        let institutional = fv?.institutionalEscrowHints.count ?? 0
        let fdesetup = fv?.fdesetupPresent == true
        let remote = Self.remoteAccess(state)
        var evidence: [Evidence] = [
            Evidence(
                type: "filevault_summary",
                detail:
                    "fileVaultOn=\(fileVaultOn.rootstockDescribe) escrowPaths=\(escrow) "
                    + "institutional=\(institutional) fdesetup=\(fdesetup) "
                    + "remote=\(remote) mdmEnrolled=\((state.mdm?.enrolled).rootstockDescribe)"
            ),
        ]
        if let fv {
            for path in (fv.escrowPathHints + fv.institutionalEscrowHints).prefix(12) {
                evidence.append(Evidence(type: "escrow_path", path: path, detail: "escrow/recovery path hint"))
            }
            for n in fv.notes.prefix(8) {
                evidence.append(Evidence(type: "fv_note", detail: n))
            }
        }
        if let protNotes = state.protections?.notes {
            for n in protNotes.prefix(4) {
                evidence.append(Evidence(type: "prot_note", detail: n))
            }
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Assess NEVER prints recovery keys, never runs fdesetup auth/recovery extraction, "
                    + "never provides offline unlock recipes. Paths and status class only."
            )
        )
        return evidence
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let fv = state.fileVaultEscrow
        let fileVaultOn = fv?.fileVaultOn ?? state.protections?.fileVaultOn
        let escrow = fv?.escrowPathHints.count ?? 0
        let institutional = fv?.institutionalEscrowHints.count ?? 0
        let fvOff = fileVaultOn == false
        let unmanaged = state.mdm?.enrolled == false
        let severity: Severity
        let title: String
        if fvOff && remoteAccess(state) {
            severity = .high
            title = "FileVault off with remote access compound (disk confidentiality gap)"
        } else if fvOff {
            severity = .medium
            title = "FileVault disabled (volume encryption posture gap)"
        } else if unmanaged && escrow + institutional > 0 {
            severity = .medium
            title = "FileVault escrow/recovery path surface on unmanaged host"
        } else {
            severity = .low
            title = "FileVault / recovery escrow posture surface"
        }
        return Finding(id: Self.id, title: title, severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1552", "T1530"], remediation: [
                    "Enable FileVault on all portable and high-value endpoints via MDM",
                    "Escrow institutional recovery keys to approved MDM only; audit escrow coverage",
                    "Disable remote access on endpoints lacking volume encryption",
                    "OPSEC: Rootstock Red never extracts or displays recovery key material",
                ], falsePositiveNotes: "Escrow preference paths may exist without active institutional escrow. "
                    + "Confirm FV status with authorized inventory tooling under ROE."), runtime: .init(confidence: fvOff ? .medium : .low, dryRunSafe: true, opsecScore: 14, esfExpected: ["OPEN"]))
    }

}
