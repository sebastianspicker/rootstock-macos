import Foundation
import RootstockCore

/// Path-to-impact: ScreenCapture / screenshot privacy dual-use depth.
public struct ScreenCapturePrivacyDualUseVector: Check {
    public static let id = "rootstock.vector.data.screencapture_privacy"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.screenCapturePrivacyDualUse
        let a = s?.screencaptureToolPaths.count ?? 0
        let b = s?.screenCaptureKitPaths.count ?? 0
        let c = s?.screenshotDropHints.count ?? 0
        let surface = s?.captureSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.screencapture_privacy_dualuse"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let compound = RemoteCompoundSignals(state: state)
        var evidence: [Evidence] = [
            Evidence(type: "screencapture_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(compound.remote) fda=\(compound.fullDiskAccess)"),
        ]
        if let s {
            evidence += VectorEvidence.paths(s.screencaptureToolPaths + s.screenCaptureKitPaths + s.screenshotDropHints, type: "screencapture_path", detail: "ScreenCapture privacy dual-use path", limit: 12)
            evidence += VectorEvidence.notes(s.notes, type: "screencapture_note", limit: 6)
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never captures screens or dumps Screen Recording TCC rows."))
        let severity = compound.surfaceSeverity(pathPairCount: a + b)
        return [Finding(id: Self.id, title: compound.remote ? "ScreenCapture privacy dual-use with remote access amplifier" : "ScreenCapture / screenshot privacy dual-use depth", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1113", "T1125", "T1005"], remediation: [
                "Inventory and baseline ScreenCapture privacy dual-use paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never captures screens or dumps Screen Recording TCC rows",
            ], falsePositiveNotes: "Stock macOS paths often exist. Elevate multi-path co-presence with remote/FDA."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]))]
    }
}
