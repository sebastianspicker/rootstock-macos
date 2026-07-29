import Foundation
import RootstockCore

/// Inventory of present LOOBins with ATT&CK-oriented tactics from the catalog.
public struct LOOBinInventoryCheck: Check {
    public static let id = "rootstock.check.lool.inventory"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let present = state.loobins.filter(\.present)
        guard !present.isEmpty else { return emptyInventoryFinding(state) }
        return [inventoryFinding(present: present)]
    }


    private func emptyInventoryFinding(_ state: CollectedState) -> [Finding] {
        guard !state.loobins.isEmpty else { return [] }
        return [Finding(
            id: "\(Self.id).none",
            title: "LOOBin inventory empty (no catalog entries present on disk)",
            severity: .info,
            category: .lool,
            resolution: .init(
                evidence: [Evidence(type: "note", detail: "Catalog scanned \(state.loobins.count) entries; none executable at expected paths")],
                attackTechniques: ["T1218"],
                remediation: ["Verify LOOBin catalog paths for this OS version"]
            ),
            runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 5)
        )]
    }

    private func inventoryFinding(present: [LOOBinHit]) -> Finding {
        var techniques = Set(present.flatMap(\.tactics))
        techniques.formUnion(Self.mapTacticsToTechniques(Array(techniques)))
        if techniques.isEmpty { techniques.insert("T1218") }
        return Finding(
            id: Self.id,
            title: "LOOBin inventory: \(present.count) present",
            severity: .info,
            category: .lool,
            resolution: .init(
                evidence: inventoryEvidence(present),
                attackTechniques: Array(techniques).sorted(),
                remediation: [
                    "Informational living-off-the-land surface for purple-team planning",
                    "Monitor abuse of dual-use binaries via ESF / EDR",
                ],
                falsePositiveNotes: "Presence of stock Apple binaries is expected on every Mac"
            ),
            runtime: .init(confidence: .high, dryRunSafe: true, opsecScore: 8, esfExpected: ["OPEN"])
        )
    }

    private func inventoryEvidence(_ present: [LOOBinHit]) -> [Evidence] {
        present.prefix(40).map { entry in
            let tactics = entry.tactics.isEmpty ? "unspecified" : entry.tactics.joined(separator: ",")
            return Evidence(type: "loobin", path: entry.path, detail: "\(entry.name) present tactics=\(tactics)")
        }
    }

    private static func mapTacticsToTechniques(_ tactics: [String]) -> [String] {
        let rules: [(terms: [String], technique: String)] = [
            (["execution"], "T1059"),
            (["persist"], "T1543.001"),
            (["credential"], "T1555"),
            (["discovery"], "T1082"),
            (["defense", "evasion"], "T1562"),
            (["lateral"], "T1021"),
            (["collection"], "T1005"),
            (["command", "c2"], "T1071"),
        ]
        let normalizedTactics = tactics.map { $0.lowercased() }
        return rules.compactMap { rule in
            normalizedTactics.contains { tactic in rule.terms.contains { tactic.contains($0) } }
                ? rule.technique
                : nil
        }
    }
}
