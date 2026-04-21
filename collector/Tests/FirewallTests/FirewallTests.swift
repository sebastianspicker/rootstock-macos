import XCTest
@testable import Firewall
import Models

final class FirewallTests: XCTestCase {

    // MARK: - Model tests

    func testFirewallStatusNodeType() {
        let status = FirewallStatus(
            enabled: true, stealthMode: false,
            allowSigned: true, allowBuiltIn: true, appRules: []
        )
        XCTAssertEqual(status.nodeType, "FirewallPolicy")
    }

    func testFirewallStatusJSONEncoding() throws {
        let status = FirewallStatus(
            enabled: true, stealthMode: true,
            allowSigned: true, allowBuiltIn: false,
            appRules: [FirewallAppRule(bundleId: "com.example.app", allowIncoming: true)]
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let data = try encoder.encode(status)
        let dict = try JSONSerialization.jsonObject(with: data) as? [String: Any]

        XCTAssertEqual(dict?["enabled"] as? Bool, true)
        XCTAssertEqual(dict?["stealth_mode"] as? Bool, true)
        XCTAssertEqual(dict?["allow_signed"] as? Bool, true)
        XCTAssertEqual(dict?["allow_built_in"] as? Bool, false)

        let rules = dict?["app_rules"] as? [[String: Any]]
        XCTAssertEqual(rules?.count, 1)
        XCTAssertEqual(rules?.first?["bundle_id"] as? String, "com.example.app")
        XCTAssertEqual(rules?.first?["allow_incoming"] as? Bool, true)
    }

    func testFirewallStatusJSONRoundTrip() throws {
        let original = FirewallStatus(
            enabled: false, stealthMode: false,
            allowSigned: false, allowBuiltIn: false, appRules: []
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(FirewallStatus.self, from: data)
        XCTAssertEqual(decoded.enabled, original.enabled)
        XCTAssertEqual(decoded.stealthMode, original.stealthMode)
        XCTAssertTrue(decoded.appRules.isEmpty)
    }

    // MARK: - ALF plist parsing

    func testParseALFPlistEnabled() {
        let source = FirewallDataSource()
        let plist: [String: Any] = [
            "globalstate": 1,
            "stealthenabled": 1,
            "allowsignedenabled": 1,
            "allowdownloadsignedenabled": 0,
            "applications": [
                ["bundleid": "com.example.app", "state": 3],
                ["bundleid": "com.example.blocked", "state": 4],
            ],
        ]
        let status = source.parseALFPlist(plist)
        XCTAssertEqual(status.enabled, true)
        XCTAssertEqual(status.stealthMode, true)
        XCTAssertEqual(status.allowSigned, false)
        XCTAssertEqual(status.allowBuiltIn, true)
        XCTAssertEqual(status.appRules.count, 2)

        let allowed = status.appRules.first { $0.bundleId == "com.example.app" }
        XCTAssertTrue(allowed?.allowIncoming == true)

        let blocked = status.appRules.first { $0.bundleId == "com.example.blocked" }
        XCTAssertTrue(blocked?.allowIncoming == false)
    }

    func testParseALFPlistSignedSoftwareToggles() {
        let source = FirewallDataSource()
        let plist: [String: Any] = [
            "globalstate": 1,
            "allowsignedenabled": 0,
            "allowdownloadsignedenabled": 1,
        ]

        let status = source.parseALFPlist(plist)

        XCTAssertEqual(status.allowSigned, true)
        XCTAssertEqual(status.allowBuiltIn, false)
    }

    func testParseALFPlistDisabled() {
        let source = FirewallDataSource()
        let plist: [String: Any] = ["globalstate": 0]
        let status = source.parseALFPlist(plist)
        XCTAssertEqual(status.enabled, false)
        XCTAssertEqual(status.stealthMode, false)
        XCTAssertTrue(status.appRules.isEmpty)
    }

    func testParseALFPlistEssentialOnly() {
        let source = FirewallDataSource()
        let plist: [String: Any] = ["globalstate": 2]
        let status = source.parseALFPlist(plist)
        XCTAssertEqual(status.enabled, true, "globalstate=2 (essential only) means enabled")
    }

    func testParseALFPlistMissingKeys() {
        let source = FirewallDataSource()
        let plist: [String: Any] = [:]
        let status = source.parseALFPlist(plist)
        XCTAssertEqual(status.enabled, false)
        XCTAssertEqual(status.stealthMode, false)
        XCTAssertEqual(status.allowSigned, false)
    }

    // MARK: - DataSource tests

    func testFirewallDataSourceMetadata() {
        let source = FirewallDataSource()
        XCTAssertEqual(source.name, "Firewall")
        XCTAssertFalse(source.requiresElevation)
    }

    func testFirewallDataSourceCollectsWithoutCrash() async {
        let source = FirewallDataSource()
        let result = await source.collect()
        // Should always return exactly 1 FirewallStatus node (even if plist unreadable)
        let statuses = result.nodes.compactMap { $0 as? FirewallStatus }
        XCTAssertEqual(statuses.count, 1, "Should return exactly one FirewallStatus node")
    }

    func testFirewallDataSourceWithMissingFile() async {
        let source = FirewallDataSource(alfPlistPath: "/nonexistent/path.plist")
        let result = await source.collect()
        let statuses = result.nodes.compactMap { $0 as? FirewallStatus }
        XCTAssertEqual(statuses.count, 1, "Should still return a status placeholder")
        XCTAssertNil(statuses[0].enabled, "Status from missing file should be unknown")
        XCTAssertFalse(result.errors.isEmpty, "Should report an error for missing plist")
    }

    func testErrorsAreRecoverable() async {
        let source = FirewallDataSource(alfPlistPath: "/nonexistent/path.plist")
        let result = await source.collect()
        for error in result.errors {
            XCTAssertTrue(error.recoverable, "All firewall errors should be recoverable")
        }
    }
}
