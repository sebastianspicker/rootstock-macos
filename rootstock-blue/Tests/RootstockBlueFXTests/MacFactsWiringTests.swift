import XCTest
import RootstockBlueCore
import RootstockMacFacts
@testable import RootstockBlueFX

/// Proves live IR posture and Autostart parsers call into RootstockMacFacts.
final class MacFactsWiringTests: XCTestCase {
    func testHostPostureProbesSharedParsers() {
        XCTAssertEqual(HostPostureProbes.parseSIPOutput("enabled"), true)
        XCTAssertEqual(HostPostureProbes.parseGatekeeperOutput("assessments disabled"), false)
        // Live enumerate without status probes still works offline-safe
        let events = HostIRPosture.enumerateLive(runStatusProbes: false)
        XCTAssertTrue(events.contains { $0.eventType == "ir.posture.host" })
        XCTAssertTrue(events.allSatisfy { $0.fields["ir.mode"] == "live" })
    }

    func testAutostartUsesLaunchdPlistFacts() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("autostart-facts-\(UUID().uuidString)", isDirectory: true)
        let la = tmp.appendingPathComponent("Library/LaunchAgents", isDirectory: true)
        try FileManager.default.createDirectory(at: la, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let plist: [String: Any] = [
            "Label": "com.fixture.agent",
            "ProgramArguments": ["/bin/echo", "hi"],
            "RunAtLoad": true,
        ]
        let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        try data.write(to: la.appendingPathComponent("com.fixture.agent.plist"))

        let events = try AutostartParser().parse(source: .directory(tmp))
        XCTAssertFalse(events.isEmpty)
        let event = try XCTUnwrap(events.first)
        XCTAssertEqual(event.fields["persistence.label"], "com.fixture.agent")
        XCTAssertEqual(event.fields["persistence.program"], "/bin/echo")
        XCTAssertEqual(event.fields["persistence.parser"], "LaunchdPlistFacts")
    }
}
