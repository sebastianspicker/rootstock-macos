import XCTest
import Foundation
@testable import MDM
import Models

final class MDMTests: XCTestCase {

    // MARK: - Model tests

    func testMDMProfileNodeType() {
        let profile = MDMProfile(
            identifier: "com.example.profile",
            displayName: "Test Profile",
            organization: "Example Corp",
            installDate: "2026-01-01 00:00:00 +0000",
            tccPolicies: []
        )
        XCTAssertEqual(profile.nodeType, "MDMProfile")
    }

    func testMDMProfileJSONEncoding() throws {
        let policy = TCCPolicy(
            service: "SystemPolicyAllFiles",
            clientBundleId: "com.example.app",
            allowed: true
        )
        let profile = MDMProfile(
            identifier: "com.example.profile",
            displayName: "Test Profile",
            organization: nil,
            installDate: nil,
            tccPolicies: [policy]
        )
        let data = try JSONEncoder().encode(profile)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        XCTAssertEqual(json["identifier"] as? String, "com.example.profile")
        XCTAssertEqual(json["display_name"] as? String, "Test Profile")
        XCTAssertNil(json["organization"])
        XCTAssertNil(json["install_date"])
        // nodeType must NOT appear in JSON
        XCTAssertNil(json["nodeType"], "nodeType must not be serialized to JSON")

        let policies = json["tcc_policies"] as! [[String: Any]]
        XCTAssertEqual(policies.count, 1)
        XCTAssertEqual(policies[0]["service"] as? String, "SystemPolicyAllFiles")
        XCTAssertEqual(policies[0]["client_bundle_id"] as? String, "com.example.app")
        XCTAssertEqual(policies[0]["allowed"] as? Bool, true)
    }

    func testTCCPolicyJSONEncoding() throws {
        let policy = TCCPolicy(service: "Microphone", clientBundleId: "com.example.conf", allowed: false)
        let data = try JSONEncoder().encode(policy)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        XCTAssertEqual(json["service"] as? String, "Microphone")
        XCTAssertEqual(json["client_bundle_id"] as? String, "com.example.conf")
        XCTAssertEqual(json["allowed"] as? Bool, false)
    }

    // MARK: - XML parsing with synthetic fixture

    func testParsesSingleProfileWithNoTCCPayload() throws {
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>_computerlevel</key>
            <array>
                <dict>
                    <key>ProfileIdentifier</key>
                    <string>com.example.mdm.profile</string>
                    <key>ProfileDisplayName</key>
                    <string>Example MDM</string>
                    <key>ProfileOrganization</key>
                    <string>Example Corp</string>
                    <key>ProfileInstallDate</key>
                    <string>2026-01-15 10:00:00 +0000</string>
                    <key>ProfileItems</key>
                    <array>
                        <dict>
                            <key>PayloadType</key>
                            <string>com.apple.mdm</string>
                            <key>PayloadContent</key>
                            <dict/>
                        </dict>
                    </array>
                </dict>
            </array>
        </dict>
        </plist>
        """
        let data = xml.data(using: .utf8)!
        let scanner = MDMProfileScanner()
        let (profiles, errors) = scanner.parseProfilesXML(data)

        XCTAssertTrue(errors.isEmpty)
        XCTAssertEqual(profiles.count, 1)
        XCTAssertEqual(profiles[0].identifier, "com.example.mdm.profile")
        XCTAssertEqual(profiles[0].displayName, "Example MDM")
        XCTAssertEqual(profiles[0].organization, "Example Corp")
        XCTAssertEqual(profiles[0].installDate, "2026-01-15 10:00:00 +0000")
        XCTAssertTrue(profiles[0].tccPolicies.isEmpty)
    }

    func testParsesTCCPolicyPayload() throws {
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>_computerlevel</key>
            <array>
                <dict>
                    <key>ProfileIdentifier</key>
                    <string>com.example.tcc.profile</string>
                    <key>ProfileDisplayName</key>
                    <string>Privacy Policy</string>
                    <key>ProfileItems</key>
                    <array>
                        <dict>
                            <key>PayloadType</key>
                            <string>com.apple.TCC.configuration-profile-policy</string>
                            <key>PayloadContent</key>
                            <dict>
                                <key>Services</key>
                                <dict>
                                    <key>SystemPolicyAllFiles</key>
                                    <array>
                                        <dict>
                                            <key>Identifier</key>
                                            <string>com.example.app</string>
                                            <key>IdentifierType</key>
                                            <string>bundleID</string>
                                            <key>Allowed</key>
                                            <true/>
                                        </dict>
                                    </array>
                                    <key>Microphone</key>
                                    <array>
                                        <dict>
                                            <key>Identifier</key>
                                            <string>com.example.conf</string>
                                            <key>IdentifierType</key>
                                            <string>bundleID</string>
                                            <key>Allowed</key>
                                            <false/>
                                        </dict>
                                    </array>
                                </dict>
                            </dict>
                        </dict>
                    </array>
                </dict>
            </array>
        </dict>
        </plist>
        """
        let data = xml.data(using: .utf8)!
        let scanner = MDMProfileScanner()
        let (profiles, errors) = scanner.parseProfilesXML(data)

        XCTAssertTrue(errors.isEmpty, "Unexpected errors: \(errors)")
        XCTAssertEqual(profiles.count, 1)

        let profile = profiles[0]
        XCTAssertEqual(profile.identifier, "com.example.tcc.profile")
        XCTAssertEqual(profile.tccPolicies.count, 2)

        let fda = profile.tccPolicies.first { $0.service == "SystemPolicyAllFiles" }
        XCTAssertNotNil(fda)
        XCTAssertEqual(fda?.clientBundleId, "com.example.app")
        XCTAssertEqual(fda?.allowed, true)

        let mic = profile.tccPolicies.first { $0.service == "Microphone" }
        XCTAssertNotNil(mic)
        XCTAssertEqual(mic?.clientBundleId, "com.example.conf")
        XCTAssertEqual(mic?.allowed, false)
    }

    func testParsesEmptyPlist() {
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict/>
        </plist>
        """
        let data = xml.data(using: .utf8)!
        let scanner = MDMProfileScanner()
        let (profiles, errors) = scanner.parseProfilesXML(data)
        XCTAssertTrue(profiles.isEmpty)
        XCTAssertTrue(errors.isEmpty)
    }

    func testParsesProfileMissingOptionalFields() {
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>_computerlevel</key>
            <array>
                <dict>
                    <key>ProfileIdentifier</key>
                    <string>com.minimal.profile</string>
                    <key>ProfileItems</key>
                    <array/>
                </dict>
            </array>
        </dict>
        </plist>
        """
        let data = xml.data(using: .utf8)!
        let scanner = MDMProfileScanner()
        let (profiles, _) = scanner.parseProfilesXML(data)
        XCTAssertEqual(profiles.count, 1)
        XCTAssertEqual(profiles[0].identifier, "com.minimal.profile")
        XCTAssertEqual(profiles[0].displayName, "com.minimal.profile")  // falls back to identifier
        XCTAssertNil(profiles[0].organization)
        XCTAssertNil(profiles[0].installDate)
    }

    func testSkipsPathBasedTCCEntries() throws {
        // Entries with IdentifierType = "path" should be skipped (we only track bundle IDs)
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>_computerlevel</key>
            <array>
                <dict>
                    <key>ProfileIdentifier</key>
                    <string>com.example.path.profile</string>
                    <key>ProfileItems</key>
                    <array>
                        <dict>
                            <key>PayloadType</key>
                            <string>com.apple.TCC.configuration-profile-policy</string>
                            <key>PayloadContent</key>
                            <dict>
                                <key>Services</key>
                                <dict>
                                    <key>Accessibility</key>
                                    <array>
                                        <dict>
                                            <key>Identifier</key>
                                            <string>/usr/bin/someTool</string>
                                            <key>IdentifierType</key>
                                            <string>path</string>
                                            <key>Allowed</key>
                                            <true/>
                                        </dict>
                                    </array>
                                </dict>
                            </dict>
                        </dict>
                    </array>
                </dict>
            </array>
        </dict>
        </plist>
        """
        let data = xml.data(using: .utf8)!
        let scanner = MDMProfileScanner()
        let (profiles, _) = scanner.parseProfilesXML(data)
        XCTAssertEqual(profiles.count, 1)
        // Path-based entries should be skipped
        XCTAssertTrue(profiles[0].tccPolicies.isEmpty, "Path-based TCC entries should be skipped")
    }

    // MARK: - DataSource metadata

    func testMDMDataSourceMetadata() {
        let ds = MDMDataSource()
        XCTAssertEqual(ds.name, "MDM")
        XCTAssertFalse(ds.requiresElevation)
    }

    // MARK: - Integration (real system)

    func testMDMDataSourceCollectsWithoutCrash() async {
        let ds = MDMDataSource()
        let result = await ds.collect()
        let profiles = result.nodes.compactMap { $0 as? MDMProfile }

        // On unmanaged Macs: 0 profiles. On managed Macs: ≥1 profile.
        XCTAssertGreaterThanOrEqual(profiles.count, 0)

        // All profiles must have non-empty identifiers
        for profile in profiles {
            XCTAssertFalse(profile.identifier.isEmpty)
        }
    }

    func testErrorsAreRecoverable() async {
        let ds = MDMDataSource()
        let result = await ds.collect()
        for error in result.errors {
            XCTAssertTrue(error.recoverable)
            XCTAssertEqual(error.source, "MDM")
        }
    }
}
