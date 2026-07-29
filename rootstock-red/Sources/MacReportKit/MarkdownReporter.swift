/// MarkdownReporter - Rootstock product source (see package README for product doctrine).
import Foundation
import RootstockCore

public enum MarkdownReporter {
    public static func render(
        _ findings: [Finding],
        state: CollectedState? = nil
    ) -> String {
        var md = "# Rootstock Red Assessment Report\n\n"
        md += "- Schema: \(RootstockCore.schemaVersion)\n"
        md += "- Platform: \(RootstockCore.version)\n"
        md += "- Findings: \(findings.count)\n\n"

        if let host = state?.host {
            md += "## Host\n\n"
            md += "- Hostname: \(host.hostname)\n"
            md += "- User: \(host.username)\n"
            md += "- OS: \(host.osVersion) (\(host.arch))\n\n"
        }

        md += "## Findings\n\n"
        if findings.isEmpty {
            md += "_No findings._\n"
            return md
        }

        md += findingsSection(findings)
        return md
    }

    private static func findingsSection(_ findings: [Finding]) -> String {
        Severity.allCases.reversed().map { severity in
            let group = findings.filter { $0.severity == severity }
            return group.isEmpty ? "" : "### \(severity.rawValue.uppercased()) (\(group.count))\n\n" + group.map(renderFinding).joined()
        }.joined()
    }

    private static func renderFinding(_ finding: Finding) -> String {
        var text = "#### `\(finding.id)` - \(finding.title)\n\n- Confidence: \(finding.confidence.rawValue)\n- Category: \(finding.category.rawValue)\n"
        if let score = finding.opsecScore { text += "- OPSEC score: \(score)\n" }
        if !finding.attackTechniques.isEmpty { text += "- ATT&CK: \(finding.attackTechniques.joined(separator: ", "))\n" }
        text += evidenceSection(finding.evidence)
        if !finding.remediation.isEmpty { text += "- Remediation: \(finding.remediation.joined(separator: "; "))\n" }
        return text + "\n"
    }

    private static func evidenceSection(_ evidence: [Evidence]) -> String {
        guard !evidence.isEmpty else { return "" }
        return "- Evidence:\n" + evidence.prefix(10).map { evidence in
            "  - \(evidence.type)\(evidence.path.map { " (`\($0)`)" } ?? ""): \(evidence.detail)\n"
        }.joined()
    }
}
