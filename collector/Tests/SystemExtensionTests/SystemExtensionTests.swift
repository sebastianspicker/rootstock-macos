import XCTest
import Foundation
@testable import SystemExtensions
import Models

final class SystemExtensionTests: XCTestCase {

    func testSystemExtensionNodeType() {
        let ext = SystemExtension(identifier: "com.example.ext", teamId: "TEAM123456", extensionType: .endpointSecurity, enabled: true)
        XCTAssertEqual(ext.nodeType, "SystemExtension")
    }

    func testSystemExtensionJSONEncoding() throws {
        let ext = SystemExtension(identifier: "com.example.ext", teamId: "TEAM123456", extensionType: .network, enabled: false)
        let data = try JSONEncoder().encode(ext)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(json["identifier"] as? String, "com.example.ext")
        XCTAssertEqual(json["extension_type"] as? String, "network")
        XCTAssertEqual(json["enabled"] as? Bool, false)
    }

    func testSystemExtensionJSONRoundTrip() throws {
        let original = SystemExtension(identifier: "com.test.driver", teamId: nil, extensionType: .driver, enabled: true)
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(SystemExtension.self, from: data)
        XCTAssertEqual(decoded.identifier, original.identifier)
        XCTAssertEqual(decoded.extensionType, original.extensionType)
    }

    func testParseSystemExtensionsOutput() {
        let output = """
        2 extension(s)
        --- com.apple.system_extension.endpoint_security
        enabled active teamID bundleID (version) name [state]
        * * X9E956P446 com.crowdstrike.falcon.Agent (7.10/7.10) Falcon Sensor [activated enabled] events=[AUTH_EXEC,NOTIFY_FORK]
        - * TEAM123456 com.example.network.filter (1.0/1.0) Network Filter [activated disabled]
        """
        let extensions = SystemExtensionDataSource.parseSystemExtensionsOutput(output)
        XCTAssertEqual(extensions.count, 2)

        XCTAssertEqual(extensions[0].identifier, "com.crowdstrike.falcon.Agent")
        XCTAssertEqual(extensions[0].teamId, "X9E956P446")
        XCTAssertEqual(extensions[0].extensionType, .endpointSecurity)
        XCTAssertTrue(extensions[0].enabled)
        XCTAssertEqual(extensions[0].subscribedEvents, ["AUTH_EXEC", "NOTIFY_FORK"])

        XCTAssertEqual(extensions[1].identifier, "com.example.network.filter")
        XCTAssertEqual(extensions[1].teamId, "TEAM123456")
        XCTAssertEqual(extensions[1].extensionType, .network)
        XCTAssertFalse(extensions[1].enabled)
        XCTAssertEqual(extensions[1].subscribedEvents, [])
    }

    func testParseSystemExtensionsMarkerFirstOutput() {
        let output = """
        --- com.example.driver (2.0/2.0) ABCDE12345 [activated waiting for user] events: AUTH_OPEN, NOTIFY_CLOSE
        """
        let extensions = SystemExtensionDataSource.parseSystemExtensionsOutput(output)
        XCTAssertEqual(extensions.count, 1)

        let ext = extensions[0]
        XCTAssertEqual(ext.identifier, "com.example.driver")
        XCTAssertEqual(ext.teamId, "ABCDE12345")
        XCTAssertEqual(ext.extensionType, .driver)
        XCTAssertFalse(ext.enabled)
        XCTAssertEqual(ext.subscribedEvents, ["AUTH_OPEN", "NOTIFY_CLOSE"])
    }

    func testParseSystemExtensionsOutputEmpty() {
        let extensions = SystemExtensionDataSource.parseSystemExtensionsOutput("")
        XCTAssertTrue(extensions.isEmpty)
    }

    func testParseSystemExtensionsOutputUnmatchedReturnsNoNodes() {
        let output = """
        1 extension(s)
        --- com.apple.system_extension.endpoint_security
        enabled active teamID bundleID (version) name [state]
        systemextensionsctl: list command failed: unavailable
        """
        let extensions = SystemExtensionDataSource.parseSystemExtensionsOutput(output)
        XCTAssertTrue(extensions.isEmpty)
    }

    func testSystemExtensionDataSourceMetadata() {
        let ds = SystemExtensionDataSource()
        XCTAssertEqual(ds.name, "System Extensions")
        XCTAssertFalse(ds.requiresElevation)
    }
}
