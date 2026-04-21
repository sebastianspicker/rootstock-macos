import XCTest
import Foundation
@testable import AuthorizationDB
import Models

final class AuthorizationDBTests: XCTestCase {

    // MARK: - Model

    func testAuthorizationRightNodeType() {
        let right = AuthorizationRight(
            name: "system.privilege.admin",
            rule: "authenticate-admin-nonshared",
            allowRoot: true,
            requireAuthentication: true
        )
        XCTAssertEqual(right.nodeType, "AuthorizationRight")
    }

    func testAuthorizationRightJSONEncoding() throws {
        let right = AuthorizationRight(
            name: "system.preferences",
            rule: "authenticate-session-owner",
            allowRoot: false,
            requireAuthentication: true
        )
        let data = try JSONEncoder().encode(right)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        XCTAssertEqual(json["name"] as? String, "system.preferences")
        XCTAssertEqual(json["rule"] as? String, "authenticate-session-owner")
        XCTAssertEqual(json["allow_root"] as? Bool, false)
        XCTAssertEqual(json["require_authentication"] as? Bool, true)
    }

    func testAuthorizationRightJSONRoundTrip() throws {
        let original = AuthorizationRight(
            name: "system.privilege.taskport",
            rule: nil,
            allowRoot: true,
            requireAuthentication: false
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(AuthorizationRight.self, from: data)
        XCTAssertEqual(decoded.name, original.name)
        XCTAssertEqual(decoded.allowRoot, original.allowRoot)
        XCTAssertEqual(decoded.requireAuthentication, original.requireAuthentication)
    }

    // MARK: - Parser

    func testParseSecurityOutputValid() {
        let plistXml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>rule</key>
            <string>authenticate-admin-nonshared</string>
            <key>allow-root</key>
            <true/>
            <key>authenticate-user</key>
            <true/>
        </dict>
        </plist>
        """
        let (right, error) = AuthorizationDBDataSource.parseSecurityOutput(
            rightName: "system.privilege.admin", output: plistXml
        )
        XCTAssertNil(error)
        XCTAssertNotNil(right)
        XCTAssertEqual(right?.name, "system.privilege.admin")
        XCTAssertEqual(right?.rule, "authenticate-admin-nonshared")
        XCTAssertTrue(right?.allowRoot ?? false)
        XCTAssertTrue(right?.requireAuthentication ?? false)
    }

    func testParseSecurityOutputRuleAsArray() {
        let plistXml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>rule</key>
            <array>
                <string>is-admin</string>
            </array>
        </dict>
        </plist>
        """
        let (right, error) = AuthorizationDBDataSource.parseSecurityOutput(
            rightName: "system.login.console", output: plistXml
        )
        XCTAssertNil(error)
        XCTAssertEqual(right?.rule, "is-admin")
    }

    func testParseSecurityOutputInvalid() {
        let (right, error) = AuthorizationDBDataSource.parseSecurityOutput(
            rightName: "test.right", output: "NOT VALID PLIST"
        )
        XCTAssertNil(right)
        XCTAssertNotNil(error)
        XCTAssertTrue(error?.contains("Cannot parse") ?? false)
    }

    // MARK: - DataSource

    func testAuthorizationDBDataSourceMetadata() {
        let ds = AuthorizationDBDataSource()
        XCTAssertEqual(ds.name, "Authorization DB")
        XCTAssertFalse(ds.requiresElevation)
    }

    func testAuthorizationDBCollectsWithoutCrash() async {
        let ds = AuthorizationDBDataSource()
        let result = await ds.collect()
        let rights = result.nodes.compactMap { $0 as? AuthorizationRight }
        // security authorizationdb should work without elevation
        XCTAssertGreaterThanOrEqual(rights.count, 0)
    }
}
