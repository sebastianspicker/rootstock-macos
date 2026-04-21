import XCTest
import Foundation
@testable import AuthorizationPlugins
import Models

final class AuthorizationPluginTests: XCTestCase {

    func testAuthorizationPluginNodeType() {
        let plugin = AuthorizationPlugin(name: "TestPlugin", path: "/Library/Security/SecurityAgentPlugins/TestPlugin.bundle", teamId: "TEAM123456")
        XCTAssertEqual(plugin.nodeType, "AuthorizationPlugin")
    }

    func testAuthorizationPluginJSONEncoding() throws {
        let plugin = AuthorizationPlugin(name: "TestPlugin", path: "/test/path.bundle", teamId: "TEAM123456")
        let data = try JSONEncoder().encode(plugin)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        XCTAssertEqual(json["name"] as? String, "TestPlugin")
        XCTAssertEqual(json["team_id"] as? String, "TEAM123456")
    }

    func testAuthorizationPluginJSONRoundTrip() throws {
        let original = AuthorizationPlugin(name: "Test", path: "/test", teamId: nil)
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(AuthorizationPlugin.self, from: data)
        XCTAssertEqual(decoded.name, original.name)
        XCTAssertNil(decoded.teamId)
    }

    func testAuthorizationPluginDataSourceMetadata() {
        let ds = AuthorizationPluginDataSource()
        XCTAssertEqual(ds.name, "Authorization Plugins")
        XCTAssertFalse(ds.requiresElevation)
    }

    func testAuthorizationPluginDataSourceCollectsWithoutCrash() async {
        let ds = AuthorizationPluginDataSource()
        let result = await ds.collect()
        XCTAssertGreaterThanOrEqual(result.nodes.count, 0)
    }
}
