import Foundation
import RootstockBlueCore
import RootstockBlueCase

public struct CaseReportStatsCounts: Sendable {
    public let events: Int
    public let byPlugin: [(plugin: String, count: Int)]
    public let byEventType: [(eventType: String, count: Int)]
    public let entityReferences: Int
    public let custodyLines: Int
}

/// Human-readable case report export for IR operators.
/// Anchors output to case custody, timeline statistics, plugin breakdowns, and
/// optional findings.
public enum CaseReport {
    public struct Stats: Sendable {
        public var caseID: String
        public var caseName: String
        public var eventCount: Int
        public var byPlugin: [(plugin: String, count: Int)]
        public var byEventType: [(eventType: String, count: Int)]
        public var entityRefCount: Int
        public var custodyLines: Int
        public var findings: [Finding]
        public var generatedAt: Date

        public init(
            caseID: String,
            caseName: String,
            counts: CaseReportStatsCounts,
            findings: [Finding] = [],
            generatedAt: Date = Date()
        ) {
            self.caseID = caseID
            self.caseName = caseName
            eventCount = counts.events
            byPlugin = counts.byPlugin
            byEventType = counts.byEventType
            entityRefCount = counts.entityReferences
            custodyLines = counts.custodyLines
            self.findings = findings
            self.generatedAt = generatedAt
        }
    }

    /// Compute stats from a real `.rsbcase` package.
    public static func collectStats(
        from package: CasePackage,
        findings: [Finding] = []
    ) throws -> Stats {
        let events = try package.loadAllEvents()
        var pluginCounts: [String: Int] = [:]
        var typeCounts: [String: Int] = [:]
        var entityCount = 0
        for e in events {
            pluginCounts[e.sourcePlugin, default: 0] += 1
            typeCounts[e.eventType, default: 0] += 1
            entityCount += e.entityRefs.count
        }
        let byPlugin = pluginCounts
            .map { (plugin: $0.key, count: $0.value) }
            .sorted { $0.count > $1.count || ($0.count == $1.count && $0.plugin < $1.plugin) }
        let byType = typeCounts
            .map { (eventType: $0.key, count: $0.value) }
            .sorted { $0.count > $1.count || ($0.count == $1.count && $0.eventType < $1.eventType) }

        var custodyLines = 0
        if let text = try? String(contentsOf: package.custodyURL, encoding: .utf8) {
            custodyLines = text.split(whereSeparator: \.isNewline).filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }.count
        }

        return Stats(
            caseID: package.manifest.caseID.uuidString,
            caseName: package.manifest.name,
            counts: .init(
                events: events.count,
                byPlugin: byPlugin,
                byEventType: byType,
                entityReferences: entityCount,
                custodyLines: custodyLines
            ),
            findings: findings
        )
    }

    /// Render a markdown IR case report (non-empty when case has events).
    public static func renderMarkdown(_ stats: Stats) -> String {
        let iso = ISO8601DateFormatter()
        return reportHeader(stats, iso: iso)
            + eventTable(title: "Events by source plugin", emptyMessage: "_No events in case._", rows: stats.byPlugin.map { ($0.plugin, $0.count) })
            + eventTable(title: "Events by type", emptyMessage: "_No event types._", rows: stats.byEventType.prefix(40).map { ($0.eventType, $0.count) })
            + findingsSection(stats.findings)
            + custodySection(stats.custodyLines)
    }

    private static func reportHeader(_ stats: Stats, iso: ISO8601DateFormatter) -> String {
        "# IR Case Report: \(stats.caseName)\n\n"
            + "- Generated: \(iso.string(from: stats.generatedAt))\n"
            + "- Case ID: `\(stats.caseID)`\n"
            + "- Timeline events: \(stats.eventCount)\n"
            + "- Entity references: \(stats.entityRefCount)\n"
            + "- Custody log entries: \(stats.custodyLines)\n"
            + "- Findings: \(stats.findings.count)\n\n"
    }

    private static func eventTable(title: String, emptyMessage: String, rows: [(String, Int)]) -> String {
        guard !rows.isEmpty else { return "## \(title)\n\n\(emptyMessage)\n\n" }
        let body = rows.map { "| \($0.0) | \($0.1) |" }.joined(separator: "\n")
        return "## \(title)\n\n| Item | Count |\n|------|------:|\n\(body)\n\n"
    }

    private static func findingsSection(_ findings: [Finding]) -> String {
        guard !findings.isEmpty else { return "## Findings\n\n_No detection findings attached to this report._\n\n" }
        return ["critical", "high", "medium", "low", "info"].reduce(into: "## Findings\n\n") { section, severity in
            let group = findings.filter { $0.severity.lowercased() == severity }
            guard !group.isEmpty else { return }
            section += "### \(severity.uppercased()) (\(group.count))\n\n"
            section += group.map(renderFinding).joined(separator: "\n") + "\n\n"
        }
    }

    private static func renderFinding(_ finding: Finding) -> String {
        var text = "- [\(finding.severity)] `\(finding.ruleID)` - \(finding.title)"
        if !finding.attackTechniques.isEmpty { text += "\n  - ATT&CK: \(finding.attackTechniques.joined(separator: ", "))" }
        if !finding.evidenceSummary.isEmpty { text += "\n  - Evidence: \(finding.evidenceSummary)" }
        return text
    }

    private static func custodySection(_ lineCount: Int) -> String {
        "## Custody\n\nChain-of-custody has \(lineCount) logged action(s). Verify hashes with `rootstock-blue case verify`.\n"
    }

    /// Write report to disk and update case custody/hashes.
    @discardableResult
    public static func exportMarkdown(
        package: CasePackage,
        to url: URL,
        findings: [Finding] = [],
        actor: String = NSUserName()
    ) throws -> Stats {
        let stats = try collectStats(from: package, findings: findings)
        let body = renderMarkdown(stats)
        try body.write(to: url, atomically: true, encoding: .utf8)
        // Also copy into case artifacts for package integrity
        let destName = "reports/\(url.lastPathComponent)"
        _ = try? package.copyArtifact(from: url, relativeName: destName)
        try package.appendCustody(
            CustodyEvent(
                actor: actor,
                action: "report",
                detail: "Exported markdown report events=\(stats.eventCount) findings=\(findings.count) path=\(url.path)"
            )
        )
        try package.updateHashes()
        return stats
    }
}
