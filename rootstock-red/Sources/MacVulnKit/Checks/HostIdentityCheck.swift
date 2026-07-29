/// Cluster/check: HostIdentityCheck - multi-signal posture ranking for assess pipeline.
import Foundation
import RootstockCore

public struct HostIdentityCheck: Check {
    public static let id = "rootstock.check.host.identity"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard let host = state.host else { return [] }
        return [
            Finding(id: Self.id, title: "Host identity inventory", severity: .info, category: .host, resolution: .init(evidence: [
                    Evidence(type: "host", detail: "hostname=\(host.hostname)"),
                    Evidence(type: "host", detail: "user=\(host.username)"),
                    Evidence(type: "host", detail: "os=\(host.osVersion) arch=\(host.arch)"),
                    Evidence(type: "host", detail: "root=\(host.isRoot)"),
                ], attackTechniques: ["T1082"], remediation: ["Informational - baseline for engagement notes"]), runtime: .init(confidence: .high, dryRunSafe: true, opsecScore: 5, esfExpected: [])),
        ]
    }
}
