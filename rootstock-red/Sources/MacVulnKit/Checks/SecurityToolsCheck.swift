/// Cluster/check: SecurityToolsCheck - multi-signal posture ranking for assess pipeline.
import Foundation
import RootstockCore

public struct SecurityToolsDetectedCheck: Check {
    public static let id = "rootstock.check.sec.tools_detected"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let present = state.securityProducts.filter(\.present)
        guard !present.isEmpty else {
            return [
                Finding(id: "\(Self.id).none", title: "No common security products detected by path heuristic", severity: .low, category: .securityProduct, resolution: .init(evidence: [
                        Evidence(
                            type: "note",
                            detail: "Heuristic only - EDR may still be present under other paths"
                        ),
                    ], attackTechniques: ["T1518.001"], remediation: ["Confirm endpoint security coverage via MDM inventory"]), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 5)),
            ]
        }
        return [
            Finding(id: Self.id, title: "Security products detected (\(present.count))", severity: .info, category: .securityProduct, resolution: .init(evidence: present.map {
                    Evidence(type: "product", path: $0.path, detail: $0.name)
                }, attackTechniques: ["T1518.001"], remediation: ["Informational for OPSEC planning and purple-team validation"]), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 8, esfExpected: ["OPEN"])),
        ]
    }
}
