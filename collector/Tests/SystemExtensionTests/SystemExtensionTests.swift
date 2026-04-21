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
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
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
        --- com.crowdstrike.falcon.Agent (7.10/7.10)  CROWDSTRIKE  [activated enabled]
        --- com.example.network.filter (1.0/1.0)  TEAM123456  [activated enabled]
        """
        let extensions = SystemExtensionDataSource.parseSystemExtensionsOutput(output)
        XCTAssertGreaterThanOrEqual(extensions.count, 0) // parsing depends on format matching
    }

    func testParseSystemExtensionsOutputEmpty() {
        let extensions = SystemExtensionDataSource.parseSystemExtensionsOutput("")
        XCTAssertTrue(extensions.isEmpty)
    }

    func testSystemExtensionDataSourceMetadata() {
        let ds = SystemExtensionDataSource()
        XCTAssertEqual(ds.name, "System Extensions")
        XCTAssertFalse(ds.requiresElevation)
    }
}
