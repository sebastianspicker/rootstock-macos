import XCTest
import RootstockCore
@testable import MacReportKit

final class FamilyOpenExporterTests: XCTestCase {
    func testBuildProducesAllowlistedShape() throws {
        var state = CollectedState()
        state.host = HostState(
            hostname: "fixture-host",
            username: "alice",
            osVersion: "15.0",
            arch: "arm64",
            processArch: "arm64"
        )
        state.protections = ProtectionsState(
            sipEnabled: true,
            gatekeeperEnabled: false,
            fileVaultOn: true
        )
        state.launchAgents = [
            LaunchAgentEntry(
                label: "com.example.agent",
                path: "/Users/alice/Library/LaunchAgents/com.example.agent.plist",
                programArguments: ["/usr/bin/true"]
            ),
        ]
        let findings = [
            Finding(id: "rootstock.check.tcc.preflight_summary", title: "TCC preflight", severity: .info, category: .tcc),
        ]

        let dict = FamilyOpenExporter.build(findings: findings, state: state)
        XCTAssertEqual(dict["schema_version"] as? Int, 1)
        XCTAssertEqual(dict["source"] as? String, "rootstock-red")
        let nodes = dict["nodes"] as? [[String: Any]] ?? []
        let types = Set(nodes.compactMap { $0["type"] as? String })
        XCTAssertTrue(types.contains("Host"))
        XCTAssertTrue(types.contains("Finding"))
        XCTAssertTrue(types.contains("Protection"))
        XCTAssertTrue(types.contains("LaunchItem"))
        let edges = dict["edges"] as? [[String: String]] ?? []
        XCTAssertFalse(edges.isEmpty)
        XCTAssertTrue(edges.allSatisfy { ["HAS_FINDING", "HAS_PROTECTION", "HAS_LAUNCH_ITEM"].contains($0["type"] ?? "") })

        // Round-trip through JSON then graph Python importer shape checks
        let data = try JSONSerialization.data(withJSONObject: dict)
        let raw = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        XCTAssertEqual(raw?["source"] as? String, "rootstock-red")
    }

    func testWriteJSON() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("family-export-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: url) }
        try FamilyOpenExporter.writeJSON(findings: [], state: CollectedState(), to: url)
        let obj = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
        XCTAssertEqual(obj?["schema_version"] as? Int, 1)
    }
}
