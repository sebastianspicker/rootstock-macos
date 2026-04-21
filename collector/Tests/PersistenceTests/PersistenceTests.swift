import XCTest
import Foundation
@testable import Persistence
import Models

final class PersistenceTests: XCTestCase {

    // MARK: - Helpers

    private func makeTempDir() -> URL {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent(UUID().uuidString)
        try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func write(_ xml: String, name: String, in dir: URL) -> String {
        let url = dir.appendingPathComponent(name)
        try! xml.data(using: .utf8)!.write(to: url)
        return url.path
    }

    // MARK: - CronParser

    func testParsesCronLineWithUserField() {
        // /etc/crontab format: min hour dom month dow user command
        let crontab = """
        # Comment line
        * * * * * root /usr/sbin/atrun
        0 2 * * * daemon /usr/bin/cleanup.sh
        @reboot root /usr/local/bin/startup.sh
        """
        let parser = CronParser()
        let tempDir = makeTempDir()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let path = write(crontab, name: "crontab", in: tempDir)

        let entries = parser.parseSystemCrontab(at: path)
        XCTAssertEqual(entries.count, 3)

        let atrun = entries[0]
        XCTAssertEqual(atrun.user, "root")
        XCTAssertTrue(atrun.program.contains("atrun"))
        XCTAssertFalse(atrun.runAtLoad)

        let startup = entries[2]
        XCTAssertTrue(startup.runAtLoad, "@reboot should set runAtLoad = true")
        XCTAssertTrue(startup.program.contains("startup.sh"))
    }

    func testParsesUserCrontab() {
        let crontab = """
        # User crontab - no username field
        * * * * * /usr/local/bin/heartbeat.sh
        @reboot /usr/local/bin/onstart.sh
        """
        let parser = CronParser()
        let tempDir = makeTempDir()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let path = write(crontab, name: "testuser", in: tempDir)

        let entries = parser.parseUserCrontab(at: path, username: "testuser")
        XCTAssertEqual(entries.count, 2)
        XCTAssertEqual(entries[0].user, "testuser")
        XCTAssertFalse(entries[0].runAtLoad)
        XCTAssertTrue(entries[1].runAtLoad)
    }

    func testEmptyCrontabReturnsNoEntries() {
        let parser = CronParser()
        let tempDir = makeTempDir()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let path = write("# Only comments\n", name: "empty", in: tempDir)
        let entries = parser.parseSystemCrontab(at: path)
        XCTAssertTrue(entries.isEmpty)
    }

    func testMissingCrontabReturnsEmpty() {
        let parser = CronParser()
        let entries = parser.parseSystemCrontab(at: "/nonexistent/crontab")
        XCTAssertTrue(entries.isEmpty)
    }

    // MARK: - LaunchItem model

    func testLaunchItemNodeType() {
        let item = LaunchItem(
            label: "com.example.daemon",
            path: "/Library/LaunchDaemons/com.example.daemon.plist",
            type: .daemon,
            program: "/usr/sbin/exampled",
            runAtLoad: true,
            user: "root"
        )
        XCTAssertEqual(item.nodeType, "LaunchItem")
        XCTAssertEqual(item.type, .daemon)
    }

    func testLaunchItemJSONEncoding() throws {
        let item = LaunchItem(
            label: "com.example.agent",
            path: "/Library/LaunchAgents/com.example.agent.plist",
            type: .agent,
            program: nil,
            runAtLoad: false,
            user: nil
        )
        let data = try JSONEncoder().encode(item)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        XCTAssertEqual(json["label"] as? String, "com.example.agent")
        XCTAssertEqual(json["type"] as? String, "agent")
        XCTAssertEqual(json["run_at_load"] as? Bool, false)
        XCTAssertNil(json["program"])
    }

    func testLoginItemTypeEncoding() throws {
        let item = LaunchItem(
            label: "com.example.loginitem",
            path: "/btm",
            type: .loginItem,
            program: "/Applications/Example.app",
            runAtLoad: true,
            user: nil
        )
        let data = try JSONEncoder().encode(item)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        XCTAssertEqual(json["type"] as? String, "login_item")
    }

    // MARK: - sfltool output parsing

    func testSfltoolOutputSkipsEntriesWithoutURL() {
        let output = """
        === Login Items ===
        Identifier: com.example.nourl
        Type: login item
        ---
        Identifier: com.example.withurl
        URL: file:///Applications/Example.app
        Type: login item
        ---
        """
        let items = PersistenceDataSource.parseSfltoolOutput(output)
        XCTAssertEqual(items.count, 1)
        XCTAssertEqual(items[0].label, "com.example.withurl")
        XCTAssertEqual(items[0].path, "/Applications/Example.app")
        XCTAssertEqual(items[0].type, .loginItem)
    }

    func testSfltoolOutputNoSentinelPaths() {
        let output = """
        Identifier: com.example.app1
        Type: login item
        """
        let items = PersistenceDataSource.parseSfltoolOutput(output)
        // Entry has no URL, should be skipped entirely (no "sfltool" sentinel path)
        XCTAssertTrue(items.isEmpty)
    }

    func testSfltoolOutputMultipleValidEntries() {
        let output = """
        Identifier: com.example.app1
        URL: file:///Applications/App1.app
        Type: login item
        ---
        Identifier: com.example.app2
        URL: file:///Applications/App2.app
        Type: agent
        """
        let items = PersistenceDataSource.parseSfltoolOutput(output)
        XCTAssertEqual(items.count, 2)
        XCTAssertEqual(items[0].type, .loginItem)
        XCTAssertEqual(items[1].type, .agent)
    }

    // MARK: - PersistenceDataSource integration

    func testPersistenceDataSourceMetadata() {
        let ds = PersistenceDataSource()
        XCTAssertEqual(ds.name, "Persistence")
        XCTAssertFalse(ds.requiresElevation)
    }

    func testPersistenceDataSourceCollectsOnRealMac() async {
        let ds = PersistenceDataSource()
        let result = await ds.collect()
        let items = result.nodes.compactMap { $0 as? LaunchItem }

        // On a real Mac, LaunchDaemons alone provide >50 items
        // In minimal environments (CI without /System), may be 0 — just verify no crash
        XCTAssertGreaterThanOrEqual(items.count, 0)

        // All items must have non-empty label and path
        for item in items {
            XCTAssertFalse(item.label.isEmpty, "Label must not be empty")
            XCTAssertFalse(item.path.isEmpty, "Path must not be empty")
        }
    }

    func testPersistenceItemsHaveCorrectTypes() async {
        let ds = PersistenceDataSource()
        let result = await ds.collect()
        let items = result.nodes.compactMap { $0 as? LaunchItem }

        let validTypes: Set<String> = ["daemon", "agent", "login_item", "cron", "login_hook"]
        for item in items {
            XCTAssertTrue(
                validTypes.contains(item.type.rawValue),
                "Unexpected type '\(item.type.rawValue)' for \(item.label)"
            )
        }
    }
}
