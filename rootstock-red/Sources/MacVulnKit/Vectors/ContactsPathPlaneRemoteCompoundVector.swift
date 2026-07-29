import Foundation
import RootstockCore

/// Wave-16 compound: Contacts path plane × remote/FDA path-to-impact.
public struct ContactsPathPlaneRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.data.contacts_path_plane_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.contactsPathPlane
        let a = s?.contactsAppPaths.count ?? 0
        let b = s?.addressBookPaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        guard compound.hasAmplifier || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "contacts_path_plane_compound", detail: "a=\(a) b=\(b) remote=\(compound.remote) fda=\(compound.fullDiskAccess) sensorThin=\(compound.sensorThin)"),
        ]
        if let s {
            for path in (s.contactsAppPaths + s.addressBookPaths).prefix(6) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Contacts path plane compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never exports contact cards or dumps AddressBook database contents."))
        let severity = compound.severity
        return [Finding(id: Self.id, title: compound.remote ? "Contacts path plane × remote compound" : "Contacts path plane × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1213", "T1005", "T1087"], remediation: [
                "Prioritize hosts co-locating Contacts path plane with remote/FDA amplifiers",
                "Use Wave-16 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ], falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]))]
    }
}
