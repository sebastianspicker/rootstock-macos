import Foundation
import XCTest
@testable import RootstockBlueCore

final class VersionMetadataTests: XCTestCase {
    private var packageRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    func testBundleVersionsAlignWithRuntimeVersion() throws {
        let expectedMarketingVersion = "0.4.0"
        XCTAssertEqual(RootstockBlueVersion.string, "\(expectedMarketingVersion)-dfir")

        let config = try String(
            contentsOf: packageRoot.appendingPathComponent("Config/Version.xcconfig"),
            encoding: .utf8
        )
        XCTAssertTrue(config.contains("MARKETING_VERSION = \(expectedMarketingVersion)"))

        for path in [
            "Apps/RootstockBlue/Info.plist",
            "Apps/RootstockBlueES/Info.plist",
        ] {
            let data = try Data(contentsOf: packageRoot.appendingPathComponent(path))
            let plist = try XCTUnwrap(
                PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
            )
            let shortVersion = try XCTUnwrap(plist["CFBundleShortVersionString"] as? String)
            XCTAssertEqual(shortVersion, expectedMarketingVersion, "\(path) must match MARKETING_VERSION")
            XCTAssertTrue(
                shortVersion.range(of: "^[0-9]+(\\.[0-9]+){1,2}$", options: .regularExpression) != nil,
                "\(path) must use a numeric CFBundleShortVersionString"
            )
            XCTAssertFalse((plist["CFBundleVersion"] as? String ?? "").isEmpty)
        }
    }

    func testTrashKeyNamedFixtureIsExplicitNonKeySentinel() throws {
        let fixture = packageRoot.appendingPathComponent(
            "Fixtures/artifacts/macos_sample/Users/alice/.Trash/id_rsa"
        )
        let content = try String(contentsOf: fixture, encoding: .utf8)
        XCTAssertEqual(
            content,
            "ROOTSTOCK_BLUE_FIXTURE_SENTINEL\nThis file exists only to exercise metadata-only trash inventory handling.\n"
        )
        XCTAssertFalse(content.lowercased().contains("begin private key"))
        XCTAssertFalse(content.lowercased().contains("openssh private key"))
    }
}
