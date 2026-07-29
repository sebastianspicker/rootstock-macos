import XCTest
import RootstockCore
@testable import MacReportKit

final class ReportTests: XCTestCase {
    func testJSONAndSARIFAndMarkdown() throws {
        let findings = [
            Finding(id: "rootstock.check.host.identity", title: "Host", severity: .info, category: .host, resolution: .init(evidence: [Evidence(type: "host", detail: "ok")]), runtime: .init(dryRunSafe: true)),
        ]
        let json = try ReportWriter.render(format: .json, findings: findings)
        XCTAssertFalse(json.isEmpty)
        let jsonl = try ReportWriter.render(format: .jsonl, findings: findings)
        XCTAssertTrue(String(data: jsonl, encoding: .utf8)?.contains("rootstock.check.host.identity") ?? false)
        let sarif = try ReportWriter.render(format: .sarif, findings: findings)
        let sarifObj = try JSONSerialization.jsonObject(with: sarif) as? [String: Any]
        XCTAssertEqual(sarifObj?["version"] as? String, "2.1.0")
        let md = try ReportWriter.render(format: .md, findings: findings)
        XCTAssertTrue(String(data: md, encoding: .utf8)?.contains("Rootstock Red Assessment") ?? false)
    }
}
