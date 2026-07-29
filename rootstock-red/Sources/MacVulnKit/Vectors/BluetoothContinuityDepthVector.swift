import Foundation
import RootstockCore

/// Path-to-impact: Bluetooth / Continuity proximity residual depth.
public struct BluetoothContinuityDepthVector: Check {
    public static let id = "rootstock.vector.network.bluetooth_continuity_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.bluetoothContinuityDepth
        let a = s?.bluetoothDaemonPaths.count ?? 0
        let b = s?.continuitySupportPaths.count ?? 0
        let c = s?.btPreferencePaths.count ?? 0
        let surface = s?.btContinuitySurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.bluetooth_continuity_depth"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "bluetooth_continuity_depth_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.bluetoothDaemonPaths + s.continuitySupportPaths + s.btPreferencePaths, type: "bluetooth_continuity_depth_path", detail: "Bluetooth Continuity depth path", limit: 12)
            evidence += VectorEvidence.notes(s.notes, type: "bluetooth_continuity_depth_note", limit: 5)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never enables Bluetooth pairing or spoofs Continuity identities."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "Bluetooth Continuity depth with remote amplifier" : "Bluetooth / Continuity proximity residual depth", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1011", "T1200", "T1040"], remediation: [
                "Inventory and baseline Bluetooth Continuity depth paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never enables Bluetooth pairing or spoofs Continuity identities",
            ], falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
