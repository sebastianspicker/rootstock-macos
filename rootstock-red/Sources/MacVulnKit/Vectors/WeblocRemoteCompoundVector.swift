import Foundation
import RootstockCore

/// Wave-12 compound: Webloc/inetloc delivery × remote/FDA path-to-impact.
public struct WeblocRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.delivery.webloc_remote_compound"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.weblocInetlocDelivery
        let a = s?.weblocSamplePaths.count ?? 0
        let b = s?.inetlocSamplePaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }

        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        let sensorThin =
            state.esf?.clientPaths.isEmpty == true
            || state.securityProducts.filter(\.present).isEmpty
        guard remote || fda || sensorThin || a + b >= 3 else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "webloc_inetloc_compound",
                detail: "a=\(a) b=\(b) remote=\(remote) fda=\(fda) sensorThin=\(sensorThin)"
            ),
        ]
        if let s {
            for path in (s.weblocSamplePaths + s.inetlocSamplePaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Webloc/inetloc delivery compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never crafts phishing webloc/inetloc payloads or rewrites Internet Location files."))

        let severity: Severity
        if remote && fda {
            severity = .high
        } else if remote || fda || sensorThin {
            severity = .medium
        } else {
            severity = .low
        }

        return [
            Finding(id: Self.id, title: remote
                    ? "Webloc/inetloc delivery × remote compound"
                    : "Webloc/inetloc delivery × impact compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1204", "T1566", "T1105"], remediation: [
                    "Prioritize hosts co-locating Webloc/inetloc delivery with remote/FDA amplifiers",
                    "Use Wave-12 lab plans under ROE for purple validation",
                    "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
                ], falsePositiveNotes: "Developer hosts may co-locate many dual-use paths; rank production remote hosts first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"])),
        ]
    }
}
