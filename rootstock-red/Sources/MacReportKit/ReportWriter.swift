/// ReportWriter - Rootstock product source (see package README for product doctrine).
import Foundation
import RootstockCore

public enum ReportWriter {
    public static func render(
        format: ReportFormat,
        findings: [Finding],
        state: CollectedState? = nil
    ) throws -> Data {
        switch format.normalized {
        case .json:
            return try JSONLReporter.renderArray(findings)
        case .jsonl:
            return try JSONLReporter.render(findings)
        case .sarif:
            return try SARIFReporter.render(findings)
        case .markdown, .md:
            let text = MarkdownReporter.render(findings, state: state)
            return Data(text.utf8)
        }
    }

    public static func write(
        format: ReportFormat,
        findings: [Finding],
        state: CollectedState? = nil,
        to url: URL
    ) throws {
        let data = try render(format: format, findings: findings, state: state)
        try data.write(to: url, options: .atomic)
    }
}
