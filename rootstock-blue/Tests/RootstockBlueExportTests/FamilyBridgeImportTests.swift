import XCTest
import RootstockBlueCase
import RootstockBlueCore
import RootstockBlueExport

final class FamilyBridgeImportTests: XCTestCase {
    func testFamilyOpenExporterShape() throws {
        let events = [
            EventEnvelope(
                identity: EventEnvelope.Identity(kind: "ir.posture.host", label: "IRPOSTURE"),
                capture: EventEnvelope.Capture(source: .collect),
                payload: EventEnvelope.Payload(properties: ["host.hostname": "blue-fixture", "ir.mode": "live"])
            ),
            EventEnvelope(
                identity: EventEnvelope.Identity(kind: "ir.posture.protection", label: "IRPOSTURE"),
                capture: EventEnvelope.Capture(source: .collect),
                payload: EventEnvelope.Payload(properties: [
                    "protection.name": "SIP", "protection.enabled": "true",
                    "protection.parser": "HostPostureProbes", "ir.mode": "live",
                ])
            ),
            EventEnvelope(
                identity: EventEnvelope.Identity(kind: "persistence.item", label: "AUTOSTART"),
                capture: EventEnvelope.Capture(source: .parser),
                payload: EventEnvelope.Payload(properties: [
                    "persistence.label": "com.example.agent",
                    "persistence.path": "/Library/LaunchAgents/com.example.agent.plist",
                    "persistence.program": "/usr/bin/true",
                    "persistence.parser": "LaunchdPlistFacts",
                ])
            ),
        ]
        let dict = FamilyOpenExporter.build(events: events, caseName: "fixture-case")
        XCTAssertEqual(dict["source"] as? String, "rootstock-blue")
        XCTAssertEqual(dict["schema_version"] as? Int, 1)
        let nodes = dict["nodes"] as? [[String: Any]] ?? []
        XCTAssertTrue(nodes.contains { ($0["type"] as? String) == "Host" })
        XCTAssertTrue(nodes.contains { ($0["type"] as? String) == "Protection" })
        XCTAssertTrue(nodes.contains { ($0["type"] as? String) == "LaunchItem" })
    }

    func testScanJSONImporterFromSyntheticFixture() throws {
        let scanURL = repoRoot()
            .appendingPathComponent("examples/demo-scan.json")
        XCTAssertTrue(FileManager.default.fileExists(atPath: scanURL.path), "demo-scan.json must exist")

        let data = try Data(contentsOf: scanURL)
        let (events, summary) = try ScanJSONImporter.events(from: data)
        XCTAssertGreaterThan(summary.tccEvents, 0)
        XCTAssertGreaterThan(summary.launchItemEvents, 0)
        XCTAssertEqual(summary.metaNotes, 1)
        XCTAssertEqual(events.count, summary.totalEvents)
        XCTAssertTrue(events.contains { $0.sourcePlugin == "collector.tcc" })
        XCTAssertTrue(events.contains { $0.sourcePlugin == "collector.persistence" })
        XCTAssertTrue(events.contains { $0.fields["family.source"] == "collector" })
        // Shared TCC catalog display name for FDA when present
        if let fda = events.first(where: {
            $0.fields[FieldTaxonomy.tccService] == "kTCCServiceSystemPolicyAllFiles"
        }) {
            XCTAssertEqual(fda.fields["tcc.service_display"], "Full Disk Access")
        }
    }

    func testScanJSONImportIntoCase() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("rsb-scan-import-\(UUID().uuidString).rsbcase")
        defer { try? FileManager.default.removeItem(at: tmp) }

        let pkg = try CasePackage.create(at: tmp, name: "scan-import-test")
        let scanURL = repoRoot().appendingPathComponent("examples/demo-scan.json")
        let summary = try ScanJSONImporter.importIntoCase(scanURL: scanURL, casePackage: pkg)
        XCTAssertGreaterThan(summary.totalEvents, 1)
        let loaded = try pkg.loadAllEvents()
        XCTAssertGreaterThanOrEqual(loaded.count, summary.totalEvents)
        try pkg.verifyLayout()
    }

    func testFindingsJSONLImporter() throws {
        let findingsURL = repoRoot()
            .appendingPathComponent("rootstock-red/Fixtures/sample_findings.jsonl")
        XCTAssertTrue(FileManager.default.fileExists(atPath: findingsURL.path))

        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("rsb-findings-import-\(UUID().uuidString).rsbcase")
        defer { try? FileManager.default.removeItem(at: tmp) }

        let pkg = try CasePackage.create(at: tmp, name: "findings-import-test")
        let count = try FindingsJSONLImporter.importIntoCase(
            findingsURL: findingsURL,
            casePackage: pkg
        )
        XCTAssertGreaterThan(count, 0)
        let loaded = try pkg.loadAllEvents()
        XCTAssertTrue(loaded.contains { $0.sourcePlugin == "rootstock-red" })
        XCTAssertTrue(loaded.contains { $0.eventType == "finding.import" })
    }

    private func repoRoot() -> URL {
        // Tests/RootstockBlueExportTests → rootstock-blue → repo root
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }
}
