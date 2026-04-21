import XCTest
@testable import Sandbox
import Models

final class SandboxTests: XCTestCase {

    // MARK: - SandboxProfile model tests

    func testSandboxProfileNodeType() {
        let profile = SandboxProfile(
            bundleId: "com.example.app",
            profileSource: "entitlements"
        )
        XCTAssertEqual(profile.nodeType, "SandboxProfile")
    }

    func testSandboxProfileJSONEncoding() throws {
        let profile = SandboxProfile(
            bundleId: "com.example.app",
            profileSource: "entitlements",
            fileReadRules: ["com.apple.security.files.user-selected.read-only"],
            fileWriteRules: [],
            machLookupRules: ["com.apple.security.temporary-exception.mach-lookup.global-name"],
            networkRules: ["com.apple.security.network.client"],
            iokitRules: [],
            exceptionCount: 2,
            hasUnconstrainedNetwork: true,
            hasUnconstrainedFileRead: false
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let data = try encoder.encode(profile)
        let dict = try JSONSerialization.jsonObject(with: data) as? [String: Any]

        XCTAssertEqual(dict?["bundle_id"] as? String, "com.example.app")
        XCTAssertEqual(dict?["profile_source"] as? String, "entitlements")
        XCTAssertEqual(dict?["exception_count"] as? Int, 2)
        XCTAssertEqual(dict?["has_unconstrained_network"] as? Bool, true)
        XCTAssertEqual(dict?["has_unconstrained_file_read"] as? Bool, false)

        let fileRead = dict?["file_read_rules"] as? [String]
        XCTAssertEqual(fileRead?.count, 1)

        let machLookup = dict?["mach_lookup_rules"] as? [String]
        XCTAssertEqual(machLookup?.count, 1)
    }

    func testSandboxProfileJSONRoundTrip() throws {
        let original = SandboxProfile(
            bundleId: "com.example.app",
            profileSource: "system",
            fileReadRules: ["rule1", "rule2"],
            fileWriteRules: ["rule3"],
            machLookupRules: [],
            networkRules: [],
            iokitRules: [],
            exceptionCount: 3,
            hasUnconstrainedNetwork: false,
            hasUnconstrainedFileRead: true
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(SandboxProfile.self, from: data)
        XCTAssertEqual(decoded.bundleId, original.bundleId)
        XCTAssertEqual(decoded.profileSource, original.profileSource)
        XCTAssertEqual(decoded.fileReadRules, original.fileReadRules)
        XCTAssertEqual(decoded.fileWriteRules, original.fileWriteRules)
        XCTAssertEqual(decoded.exceptionCount, original.exceptionCount)
        XCTAssertEqual(decoded.hasUnconstrainedNetwork, original.hasUnconstrainedNetwork)
        XCTAssertEqual(decoded.hasUnconstrainedFileRead, original.hasUnconstrainedFileRead)
    }

    // MARK: - SandboxProfileParser tests

    func testParseBasicAllowRules() {
        let parser = SandboxProfileParser()
        let sbpl = """
        (version 1)
        (allow file-read* (subpath "/usr/share"))
        (allow file-write* (subpath "/tmp"))
        (allow mach-lookup (global-name "com.apple.SecurityServer"))
        (allow network-outbound)
        (allow iokit-open (iokit-user-client-class "IOHIDParamUserClient"))
        """
        let result = parser.parse(sbpl)
        XCTAssertEqual(result.fileReadRules.count, 1)
        XCTAssertEqual(result.fileWriteRules.count, 1)
        XCTAssertEqual(result.machLookupRules.count, 1)
        XCTAssertEqual(result.networkRules.count, 1)
        XCTAssertEqual(result.iokitRules.count, 1)
    }

    func testParseDenyRules() {
        let parser = SandboxProfileParser()
        let sbpl = """
        (deny file-read* (subpath "/private"))
        (deny network-outbound)
        """
        let result = parser.parse(sbpl)
        XCTAssertEqual(result.fileReadRules.count, 1)
        XCTAssertTrue(result.fileReadRules[0].contains("deny"))
        XCTAssertEqual(result.networkRules.count, 1)
        XCTAssertTrue(result.networkRules[0].contains("deny"))
    }

    func testParseEmptyProfile() {
        let parser = SandboxProfileParser()
        let result = parser.parse("")
        XCTAssertTrue(result.fileReadRules.isEmpty)
        XCTAssertTrue(result.fileWriteRules.isEmpty)
        XCTAssertTrue(result.machLookupRules.isEmpty)
        XCTAssertTrue(result.networkRules.isEmpty)
        XCTAssertTrue(result.iokitRules.isEmpty)
    }

    func testParseMultipleRulesSameCategory() {
        let parser = SandboxProfileParser()
        let sbpl = """
        (allow file-read* (subpath "/usr/share"))
        (allow file-read* (subpath "/Library"))
        (allow file-read-data (literal "/etc/hosts"))
        """
        let result = parser.parse(sbpl)
        XCTAssertEqual(result.fileReadRules.count, 3)
    }

    func testExtractRulesBasic() {
        let parser = SandboxProfileParser()
        let rules = parser.extractRules(from: "(allow mach-lookup)")
        XCTAssertEqual(rules.count, 1)
        XCTAssertEqual(rules[0].action, "allow")
        XCTAssertEqual(rules[0].operation, "mach-lookup")
    }

    // MARK: - SandboxDataSource tests

    func testBuildProfileForSandboxedApp() {
        let source = SandboxDataSource(systemProfilesPath: "/nonexistent")
        let app = Application(
            name: "TestApp",
            bundleId: "com.example.test",
            path: "/Applications/TestApp.app",
            version: "1.0",
            teamId: "TEST123",
            hardenedRuntime: true,
            libraryValidation: true,
            isElectron: false,
            isSystem: false,
            signed: true,
            isSandboxed: true,
            sandboxExceptions: ["com.apple.security.files.user-selected.read-write"],
            entitlements: [
                EntitlementInfo(
                    name: "com.apple.security.network.client",
                    isPrivate: false,
                    category: "network",
                    isSecurityCritical: false
                ),
                EntitlementInfo(
                    name: "com.apple.security.files.user-selected.read-write",
                    isPrivate: false,
                    category: "sandbox",
                    isSecurityCritical: false
                ),
            ]
        )
        let profile = source.buildProfile(for: app)
        XCTAssertNotNil(profile)
        XCTAssertEqual(profile?.bundleId, "com.example.test")
        XCTAssertEqual(profile?.profileSource, "entitlements")
        XCTAssertTrue(profile?.networkRules.contains("com.apple.security.network.client") == true)
        XCTAssertTrue(profile?.fileReadRules.contains("com.apple.security.files.user-selected.read-write") == true)
        XCTAssertTrue(profile?.fileWriteRules.contains("com.apple.security.files.user-selected.read-write") == true)
        XCTAssertTrue(profile?.hasUnconstrainedNetwork == true)
        XCTAssertFalse(profile?.hasUnconstrainedFileRead == true)
        XCTAssertEqual(profile?.exceptionCount, 1)
    }

    func testBuildProfileReturnsNilForNonSandboxedApp() {
        let source = SandboxDataSource(systemProfilesPath: "/nonexistent")
        let app = Application(
            name: "TestApp",
            bundleId: "com.example.test",
            path: "/Applications/TestApp.app",
            version: "1.0",
            teamId: nil,
            hardenedRuntime: false,
            libraryValidation: false,
            isElectron: false,
            isSystem: false,
            signed: true,
            isSandboxed: false
        )
        let profile = source.buildProfile(for: app)
        XCTAssertNil(profile)
    }

    func testBuildProfileDetectsUnconstrainedFileRead() {
        let source = SandboxDataSource(systemProfilesPath: "/nonexistent")
        let app = Application(
            name: "TestApp",
            bundleId: "com.example.test",
            path: "/Applications/TestApp.app",
            version: "1.0",
            teamId: nil,
            hardenedRuntime: false,
            libraryValidation: false,
            isElectron: false,
            isSystem: false,
            signed: true,
            isSandboxed: true,
            entitlements: [
                EntitlementInfo(
                    name: "com.apple.security.files.all",
                    isPrivate: false,
                    category: "sandbox",
                    isSecurityCritical: true
                ),
            ]
        )
        let profile = source.buildProfile(for: app)
        XCTAssertNotNil(profile)
        XCTAssertTrue(profile!.hasUnconstrainedFileRead)
    }

    func testEnrichApplications() {
        let source = SandboxDataSource(systemProfilesPath: "/nonexistent")
        var apps = [
            Application(
                name: "Sandboxed",
                bundleId: "com.example.sandboxed",
                path: "/Applications/Sandboxed.app",
                version: "1.0",
                teamId: nil,
                hardenedRuntime: false,
                libraryValidation: false,
                isElectron: false,
                isSystem: false,
                signed: true,
                isSandboxed: true,
                entitlements: [
                    EntitlementInfo(
                        name: "com.apple.security.network.client",
                        isPrivate: false,
                        category: "network",
                        isSecurityCritical: false
                    ),
                ]
            ),
            Application(
                name: "NotSandboxed",
                bundleId: "com.example.notsandboxed",
                path: "/Applications/NotSandboxed.app",
                version: "1.0",
                teamId: nil,
                hardenedRuntime: false,
                libraryValidation: false,
                isElectron: false,
                isSystem: false,
                signed: true,
                isSandboxed: false
            ),
        ]
        let count = source.enrich(applications: &apps)
        XCTAssertEqual(count, 1)
        XCTAssertNotNil(apps[0].sandboxProfile)
        XCTAssertNil(apps[1].sandboxProfile)
    }

    func testLoadSystemProfileMissing() {
        let source = SandboxDataSource(systemProfilesPath: "/nonexistent/path")
        let profile = source.loadSystemProfile(for: "com.example.test")
        XCTAssertNil(profile)
    }

    // MARK: - Application model integration

    func testApplicationWithSandboxProfileEncoding() throws {
        let profile = SandboxProfile(
            bundleId: "com.example.app",
            profileSource: "entitlements",
            exceptionCount: 0
        )
        let app = Application(
            name: "TestApp",
            bundleId: "com.example.app",
            path: "/Applications/TestApp.app",
            version: "1.0",
            teamId: nil,
            hardenedRuntime: true,
            libraryValidation: true,
            isElectron: false,
            isSystem: false,
            signed: true,
            isSandboxed: true,
            sandboxProfile: profile
        )
        let data = try JSONEncoder().encode(app)
        let dict = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        XCTAssertNotNil(dict?["sandbox_profile"])
    }

    func testApplicationWithoutSandboxProfileEncoding() throws {
        let app = Application(
            name: "TestApp",
            bundleId: "com.example.app",
            path: "/Applications/TestApp.app",
            version: "1.0",
            teamId: nil,
            hardenedRuntime: true,
            libraryValidation: true,
            isElectron: false,
            isSystem: false,
            signed: true,
            isSandboxed: false
        )
        let data = try JSONEncoder().encode(app)
        let decoded = try JSONDecoder().decode(Application.self, from: data)
        XCTAssertNil(decoded.sandboxProfile)
    }
}
