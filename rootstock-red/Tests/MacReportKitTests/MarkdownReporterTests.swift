import Testing
@testable import MacReportKit
import RootstockCore

@Suite struct MarkdownReporterTests {
    @Test func evidenceIsRenderedAsLiteralSingleLineText() {
        let finding = Finding(
            id: "RTEST-1`\n## forged",
            title: "[click](javascript:alert(1))",
            severity: .high,
            category: .persist,
            resolution: .init(
                evidence: [Evidence(type: "label", path: "/tmp/`escape", detail: "line one\n![x](https://attacker.test)")],
                remediation: ["<script>alert(1)</script>"]
            ),
            runtime: .init(confidence: .high)
        )

        let report = MarkdownReporter.render([finding])

        #expect(!report.contains("\n## forged"))
        #expect(report.contains("\\[click\\]"))
        #expect(report.contains("&lt;script&gt;"))
        #expect(!report.contains("\n![x]"))
    }
}
