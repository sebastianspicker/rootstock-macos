import Foundation
import RootstockCore

/// Minimal SARIF 2.1.0 emitter for findings.
public enum SARIFReporter {
    public static func render(_ findings: [Finding]) throws -> Data {
        try JSONSerialization.data(withJSONObject: sarif(findings), options: [.prettyPrinted, .sortedKeys])
    }

    private static func sarif(_ findings: [Finding]) -> [String: Any] {
        [
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                [
                    "tool": [
                        "driver": [
                            "name": "Rootstock Red",
                            "version": RootstockCore.version,
                            "informationUri": "https://github.com/example/rootstock-red",
                            "rules": findings.map(rule),
                        ],
                    ],
                    "results": findings.map(result),
                ],
            ],
        ]
    }

    private static func result(_ finding: Finding) -> [String: Any] {
        var result: [String: Any] = ["ruleId": finding.id, "level": level(for: finding.severity), "message": ["text": finding.title]]
        let locations = finding.evidence.compactMap(location)
        if !locations.isEmpty { result["locations"] = locations }
        if !finding.attackTechniques.isEmpty { result["properties"] = ["attackTechniques": finding.attackTechniques] }
        return result
    }

    private static func rule(_ finding: Finding) -> [String: Any] { ["id": finding.id, "name": finding.id, "shortDescription": ["text": finding.title], "fullDescription": ["text": finding.evidence.map(\.detail).joined(separator: "; ")], "properties": ["severity": finding.severity.rawValue, "category": finding.category.rawValue]] }
    private static func location(_ evidence: Evidence) -> [String: Any]? { evidence.path.map { ["physicalLocation": ["artifactLocation": ["uri": $0]]] } }
    private static func level(for severity: Severity) -> String { severity == .medium ? "warning" : severity == .high || severity == .critical ? "error" : "note" }
}
