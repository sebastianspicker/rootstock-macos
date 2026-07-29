import Foundation
import RootstockCore

/// Path-to-impact: Contacts database path residual plane.
public struct ContactsPathPlaneVector: Check {
    public static let id = "rootstock.vector.data.contacts_path_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.contactsPathPlane
        let a = s?.contactsAppPaths.count ?? 0
        let b = s?.addressBookPaths.count ?? 0
        let c = s?.contactsPrefPaths.count ?? 0
        let surface = s?.contactsSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.contacts_path_plane"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "contacts_path_plane_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.contactsAppPaths + s.addressBookPaths + s.contactsPrefPaths, type: "contacts_path_plane_path", detail: "Contacts path plane path", limit: 10)
            evidence += VectorEvidence.notes(s.notes, type: "contacts_path_plane_note", limit: 4)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never exports contact cards or dumps AddressBook database contents."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Contacts path plane with remote amplifier" : "Contacts database path residual plane", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1213", "T1005", "T1087"], remediation: [
                "Inventory and baseline Contacts path plane paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never exports contact cards or dumps AddressBook database contents",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
