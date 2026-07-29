/// ReportFormat - Rootstock product source (see package README for product doctrine).
import Foundation

public enum ReportFormat: String, Sendable, CaseIterable {
    case json
    case jsonl
    case sarif
    case markdown
    case md

    public var normalized: ReportFormat {
        self == .md ? .markdown : self
    }
}
