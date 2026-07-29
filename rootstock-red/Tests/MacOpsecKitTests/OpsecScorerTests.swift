import XCTest
import RootstockCore
@testable import MacOpsecKit

final class OpsecScorerTests: XCTestCase {
    func testScoreIncreasesWithSignals() {
        let scorer = OpsecScorer()
        let quiet = scorer.score(OpsecSignals())
        let noisy = scorer.score(
            OpsecSignals(
                processSpawns: 3,
                sensitiveFileOpens: 2,
                tccDomains: ["FullDiskAccess"],
                networkEgress: true,
                userVisible: true,
                esfEventClasses: ["NOTIFY_OPEN", "NOTIFY_WRITE"],
                sensitivePathReads: 2,
                appleEvents: true
            )
        )
        XCTAssertEqual(quiet, 0)
        XCTAssertGreaterThan(noisy, quiet)
        XCTAssertLessThanOrEqual(noisy, 100)
    }

    func testScoreMonotonicityESFAndTCC() {
        let scorer = OpsecScorer()
        let baseline = scorer.score(OpsecSignals())
        let withESF = scorer.score(
            OpsecSignals(esfEventClasses: ["NOTIFY_OPEN", "NOTIFY_WRITE", "NOTIFY_EXEC"])
        )
        let withESFAndTCC = scorer.score(
            OpsecSignals(
                tccDomains: ["FullDiskAccess", "Accessibility"],
                esfEventClasses: ["NOTIFY_OPEN", "NOTIFY_WRITE", "NOTIFY_EXEC"],
                sensitivePathReads: 1
            )
        )
        let withAll = scorer.score(
            OpsecSignals(
                processSpawns: 1,
                sensitiveFileOpens: 2,
                tccDomains: ["FullDiskAccess", "Accessibility"],
                networkEgress: true,
                userVisible: true,
                esfEventClasses: ["NOTIFY_OPEN", "NOTIFY_WRITE", "NOTIFY_EXEC"],
                sensitivePathReads: 2,
                appleEvents: true
            )
        )
        XCTAssertGreaterThan(withESF, baseline)
        XCTAssertGreaterThanOrEqual(withESFAndTCC, withESF)
        XCTAssertGreaterThan(withAll, withESFAndTCC)
        XCTAssertLessThanOrEqual(withAll, 100)
    }

    func testAnnotateFillsESFFromCategoryAndAlwaysScores() {
        var host = Finding(id: "h", title: "host", severity: .info, category: .host)
        host = OpsecScorer().annotate(host)
        XCTAssertEqual(host.esfExpected, [])
        XCTAssertNotNil(host.opsecScore)
        XCTAssertEqual(host.opsecScore, 0)
        XCTAssertTrue(host.evidence.contains { $0.type == "opsec" })

        var persist = Finding(id: "p", title: "persist", severity: .medium, category: .persist, resolution: .init(evidence: [Evidence(type: "path", path: "/Users/a/Library/LaunchAgents/x.plist", detail: "x")]))
        persist = OpsecScorer().annotate(persist)
        XCTAssertEqual(persist.esfExpected, ["OPEN", "WRITE"])
        XCTAssertNotNil(persist.opsecScore)
        XCTAssertGreaterThan(persist.opsecScore ?? 0, host.opsecScore ?? 0)

        var tcc = Finding(id: "t", title: "tcc", severity: .info, category: .tcc, resolution: .init(evidence: [
                Evidence(
                    type: "path",
                    path: "/Library/Application Support/com.apple.TCC/TCC.db",
                    detail: "tcc"
                ),
            ]), runtime: .init(tccDomains: ["FullDiskAccess"]))
        tcc = OpsecScorer().annotate(tcc)
        XCTAssertEqual(tcc.esfExpected, ["OPEN"])
        XCTAssertGreaterThan(tcc.opsecScore ?? 0, 0)

        var auth = Finding(id: "a", title: "auth", severity: .low, category: .auth)
        auth = OpsecScorer().annotate(auth)
        XCTAssertEqual(auth.esfExpected, ["OPEN"])
    }

    func testAnnotatePreservesExplicitESF() {
        var finding = Finding(id: "t", title: "t", severity: .info, category: .tcc, runtime: .init(tccDomains: ["Accessibility"], esfExpected: ["USER_PROMPT"]))
        finding = OpsecScorer().annotate(finding)
        XCTAssertEqual(finding.esfExpected, ["USER_PROMPT"])
        XCTAssertNotNil(finding.opsecScore)
        XCTAssertGreaterThan(finding.opsecScore ?? 0, 0)
        XCTAssertTrue(finding.evidence.contains { $0.type == "opsec" })
    }

    func testESFCatalogNotifyMapping() {
        let mapped = OpsecESFCatalog.notifyEventNames(from: ["OPEN", "WRITE", "EXEC", "USER_PROMPT"])
        XCTAssertEqual(
            mapped,
            ["NOTIFY_OPEN", "NOTIFY_WRITE", "NOTIFY_EXEC", "USER_PROMPT"]
        )
        XCTAssertEqual(
            OpsecESFCatalog.defaultShortClasses(for: .persist),
            ["OPEN", "WRITE"]
        )
        XCTAssertTrue(OpsecESFCatalog.isSensitivePath("/Users/x/Library/Messages/chat.db"))
        XCTAssertFalse(OpsecESFCatalog.isSensitivePath("/usr/bin/true"))
    }
}
