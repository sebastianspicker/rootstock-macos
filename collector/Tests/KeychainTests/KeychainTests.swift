import XCTest
import Foundation
@testable import Keychain
import Models

final class KeychainTests: XCTestCase {

    // MARK: - Model tests

    func testKeychainItemNodeType() {
        let item = KeychainItem(
            label: "Test Credential",
            kind: .genericPassword,
            service: "com.example.service",
            accessGroup: "TEAMID.com.example",
            trustedApps: ["com.example.app"]
        )
        XCTAssertEqual(item.nodeType, "KeychainItem")
    }

    func testKeychainItemJSONEncoding() throws {
        let item = KeychainItem(
            label: "My WiFi",
            kind: .internetPassword,
            service: "Airport",
            accessGroup: nil,
            trustedApps: ["com.apple.airport"]
        )
        let data = try JSONEncoder().encode(item)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        XCTAssertEqual(json["label"] as? String, "My WiFi")
        XCTAssertEqual(json["kind"] as? String, "internet_password")
        XCTAssertEqual(json["service"] as? String, "Airport")
        XCTAssertNil(json["access_group"])
        XCTAssertEqual(json["trusted_apps"] as? [String], ["com.apple.airport"])
        // nodeType must NOT appear in JSON (not a CodingKey)
        XCTAssertNil(json["nodeType"], "nodeType must not be serialized to JSON")
    }

    func testKeychainItemKindRawValues() {
        XCTAssertEqual(KeychainItem.Kind.genericPassword.rawValue, "generic_password")
        XCTAssertEqual(KeychainItem.Kind.internetPassword.rawValue, "internet_password")
        XCTAssertEqual(KeychainItem.Kind.certificate.rawValue, "certificate")
        XCTAssertEqual(KeychainItem.Kind.key.rawValue, "key")
    }

    func testKeychainItemDefaultsForOptionalFields() throws {
        let item = KeychainItem(
            label: "Minimal",
            kind: .certificate,
            service: nil,
            accessGroup: nil,
            trustedApps: []
        )
        XCTAssertNil(item.service)
        XCTAssertNil(item.accessGroup)
        XCTAssertTrue(item.trustedApps.isEmpty)

        let data = try JSONEncoder().encode(item)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        XCTAssertNil(json["service"])
        XCTAssertNil(json["access_group"])
        let apps = json["trusted_apps"] as? [String]
        XCTAssertEqual(apps, [])
    }

    // MARK: - DataSource metadata

    func testKeychainDataSourceMetadata() {
        let ds = KeychainDataSource()
        XCTAssertEqual(ds.name, "Keychain")
        XCTAssertFalse(ds.requiresElevation)
    }

    // MARK: - Integration (real system)

    func testKeychainDataSourceCollectsWithoutCrash() async {
        let ds = KeychainDataSource()
        let result = await ds.collect()
        let items = result.nodes.compactMap { $0 as? KeychainItem }

        // On a real Mac with an unlocked login keychain, we expect ≥0 items.
        // In CI or with a locked keychain, 0 items + errors is acceptable.
        XCTAssertGreaterThanOrEqual(items.count, 0)

        // All collected items must have non-empty labels
        for item in items {
            XCTAssertFalse(item.label.isEmpty, "Keychain item label must not be empty")
        }
    }

    func testKeychainItemsHaveValidKinds() async {
        let ds = KeychainDataSource()
        let result = await ds.collect()
        let items = result.nodes.compactMap { $0 as? KeychainItem }

        let validKinds: Set<String> = ["generic_password", "internet_password", "certificate", "key"]
        for item in items {
            XCTAssertTrue(
                validKinds.contains(item.kind.rawValue),
                "Unexpected kind '\(item.kind.rawValue)' for '\(item.label)'"
            )
        }
    }

    func testKeychainItemsHaveNoSecretData() async throws {
        // Verify that no known secret-data keys appear in serialized output
        let ds = KeychainDataSource()
        let result = await ds.collect()
        let items = result.nodes.compactMap { $0 as? KeychainItem }

        for item in items {
            let encoded = try JSONEncoder().encode(item)
            let json = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]

            // These keys must NEVER appear in output
            let forbidden = ["v_Data", "password", "secret", "key_data", "value_data"]
            for key in forbidden {
                XCTAssertNil(
                    json[key],
                    "Secret key '\(key)' found in keychain item '\(item.label)'"
                )
            }
        }
    }

    func testErrorsAreRecoverable() async {
        let ds = KeychainDataSource()
        let result = await ds.collect()

        // All keychain errors should be marked recoverable (graceful degradation)
        for error in result.errors {
            XCTAssertTrue(error.recoverable, "Keychain error should be recoverable: \(error.message)")
            XCTAssertEqual(error.source, "Keychain")
        }
    }
}
