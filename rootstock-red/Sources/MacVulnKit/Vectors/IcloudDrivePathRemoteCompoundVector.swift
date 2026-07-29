import Foundation
import RootstockCore

/// Wave-14 compound: iCloud Drive path plane × remote/FDA path-to-impact.
public struct IcloudDrivePathRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.data.icloud_drive_path_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.icloudDrivePath
        let a = s?.mobileDocumentsPaths.count ?? 0
        let b = s?.icloudDrivePaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        guard compound.hasAmplifier || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "icloud_drive_path_compound", detail: "a=\(a) b=\(b) remote=\(compound.remote) fda=\(compound.fullDiskAccess) sensorThin=\(compound.sensorThin)"),
        ]
        if let s {
            for path in (s.mobileDocumentsPaths + s.icloudDrivePaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "iCloud Drive path plane compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never enumerates iCloud file contents or exfiltrates Mobile Documents."))
        let severity = compound.severity
        return [Finding(id: Self.id, title: compound.remote ? "iCloud Drive path plane × remote compound" : "iCloud Drive path plane × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1530", "T1005", "T1567"], remediation: [
                "Prioritize hosts co-locating iCloud Drive path plane with remote/FDA amplifiers",
                "Use Wave-14 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ], falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]))]
    }
}
