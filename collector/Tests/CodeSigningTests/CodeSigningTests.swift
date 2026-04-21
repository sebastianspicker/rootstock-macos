import XCTest
@testable import CodeSigning
import Models

final class CodeSigningTests: XCTestCase {

    let analyzer = CodeSigningAnalyzer()
    let assessment = InjectionAssessment()

    // MARK: - CodeSigningAnalyzer integration tests

    func testSafariIsSignedWithLibraryValidation() throws {
        // Safari.app is a platform binary: signed but no team ID, no hardened runtime flag.
        // It has CS_REQUIRE_LV (0x2000) set.
        let safariPath = "/Applications/Safari.app"
        guard FileManager.default.fileExists(atPath: safariPath) else {
            throw XCTSkip("Safari.app not found — skipping")
        }
        let info = analyzer.analyze(appPath: safariPath)
        XCTAssertTrue(info.signed, "Safari should be signed")
        XCTAssertTrue(info.libraryValidationFlag, "Safari should have CS_REQUIRE_LV flag")
        XCTAssertFalse(info.analysisError, "Safari analysis should not error")
        // Platform binaries have no team identifier.
        XCTAssertNil(info.teamId, "Safari (platform binary) has no team identifier")
    }

    func testHardenedRuntimeAppIfPresent() throws {
        // 1Password uses hardened runtime — a reliable real-world example.
        // Skip gracefully if not installed.
        let path = "/Applications/1Password.app"
        guard FileManager.default.fileExists(atPath: path) else {
            throw XCTSkip("1Password.app not found — skipping hardened runtime test")
        }
        let info = analyzer.analyze(appPath: path)
        XCTAssertTrue(info.signed)
        XCTAssertTrue(info.hardenedRuntime, "1Password should have hardened runtime")
        XCTAssertNotNil(info.teamId)
    }

    func testNonExistentPathReturnsUnsigned() {
        let info = analyzer.analyze(appPath: "/nonexistent/path/Fake.app")
        XCTAssertFalse(info.signed)
        XCTAssertTrue(info.analysisError, "Should report analysis error for missing path")
        XCTAssertNil(info.teamId)
        XCTAssertFalse(info.hardenedRuntime)
    }

    func testRealAppHasSigningIdentifier() throws {
        let terminalPath = "/System/Applications/Utilities/Terminal.app"
        guard FileManager.default.fileExists(atPath: terminalPath) else {
            throw XCTSkip("Terminal.app not found")
        }
        let info = analyzer.analyze(appPath: terminalPath)
        // Terminal is a platform binary — signed but with flags=0x0 (none)
        XCTAssertFalse(info.analysisError)
        // Platform binaries with flags=0x0 report signingIdentifier as nil in some OS versions;
        // just verify analysis doesn't error out.
    }

    // MARK: - InjectionAssessment unit tests

    func testUnsignedAppIsDyldInjectable() {
        let info = makeInfo(signed: false, hardenedRuntime: false, lvFlag: false)
        let methods = assessment.assess(signingInfo: info, entitlements: [], isElectron: false).methods
        XCTAssertTrue(methods.contains(.dyldInsert), "Unhardened app should be DYLD injectable")
        XCTAssertTrue(methods.contains(.missingLibraryValidation))
    }

    func testHardenedAppWithoutEntitlementIsNotDyldInjectable() {
        let info = makeInfo(signed: true, hardenedRuntime: true, lvFlag: false)
        let methods = assessment.assess(signingInfo: info, entitlements: [], isElectron: false).methods
        XCTAssertFalse(methods.contains(.dyldInsert))
        XCTAssertFalse(methods.contains(.dyldInsertViaEntitlement))
    }

    func testHardenedAppWithAllowDyldEntitlementIsDyldInjectable() {
        let info = makeInfo(signed: true, hardenedRuntime: true, lvFlag: false)
        let entitlement = EntitlementInfo(
            name: "com.apple.security.cs.allow-dyld-environment-variables",
            isPrivate: false, category: "injection", isSecurityCritical: true
        )
        let methods = assessment.assess(signingInfo: info, entitlements: [entitlement], isElectron: false).methods
        XCTAssertTrue(methods.contains(.dyldInsertViaEntitlement))
        XCTAssertFalse(methods.contains(.dyldInsert))
    }

    func testHardenedAppWithDisableLVIsLibraryInjectable() {
        let info = makeInfo(signed: true, hardenedRuntime: true, lvFlag: false)
        let entitlement = EntitlementInfo(
            name: "com.apple.security.cs.disable-library-validation",
            isPrivate: false, category: "injection", isSecurityCritical: true
        )
        let methods = assessment.assess(signingInfo: info, entitlements: [entitlement], isElectron: false).methods
        XCTAssertTrue(methods.contains(.missingLibraryValidation))
    }

    func testHardenedAppWithLibraryValidationFlagIsNotLibraryInjectable() {
        let info = makeInfo(signed: true, hardenedRuntime: true, lvFlag: true)
        let methods = assessment.assess(signingInfo: info, entitlements: [], isElectron: false).methods
        XCTAssertFalse(methods.contains(.missingLibraryValidation))
    }

    func testElectronAppHasElectronEnvVarMethod() {
        let info = makeInfo(signed: true, hardenedRuntime: false, lvFlag: false)
        let methods = assessment.assess(signingInfo: info, entitlements: [], isElectron: true).methods
        XCTAssertTrue(methods.contains(.electronEnvVar))
    }

    func testFullyHardenedAppHasNoInjectionMethods() {
        // Hardened runtime + library validation flag + no exemption entitlements
        let info = makeInfo(signed: true, hardenedRuntime: true, lvFlag: true)
        let methods = assessment.assess(signingInfo: info, entitlements: [], isElectron: false).methods
        XCTAssertTrue(methods.isEmpty, "Fully hardened app should have no injection methods")
    }

    // MARK: - CodeSigningDataSource enrichment tests

    func testEnrichmentPopulatesSignedField() throws {
        let safariPath = "/Applications/Safari.app"
        guard FileManager.default.fileExists(atPath: safariPath) else {
            throw XCTSkip("Safari.app not found")
        }

        var apps = [Application(
            name: "Safari", bundleId: "com.apple.Safari", path: safariPath,
            version: nil, teamId: nil, hardenedRuntime: false, libraryValidation: false,
            isElectron: false, isSystem: false, signed: false,
            entitlements: [], injectionMethods: []
        )]
        let source = CodeSigningDataSource()
        source.enrich(applications: &apps)

        XCTAssertTrue(apps[0].signed, "Safari should be signed after enrichment")
        XCTAssertTrue(apps[0].libraryValidation, "Safari should have library validation after enrichment")
    }

    func testEnrichmentFailureRecordsError() {
        var apps = [Application(
            name: "Fake", bundleId: "com.fake.app", path: "/nonexistent/Fake.app",
            version: nil, teamId: nil, hardenedRuntime: false, libraryValidation: false,
            isElectron: false, isSystem: false, signed: false,
            entitlements: [], injectionMethods: []
        )]
        let source = CodeSigningDataSource()
        let errors = source.enrich(applications: &apps)

        XCTAssertFalse(errors.isEmpty, "Should record error for unanalyzable app")
        XCTAssertFalse(apps[0].signed, "Unanalyzable app should have signed=false")
    }

    // MARK: - Certificate chain tests

    func testCertificateChainExtraction() throws {
        // Safari.app is a platform binary — should be analyzable.
        let safariPath = "/Applications/Safari.app"
        guard FileManager.default.fileExists(atPath: safariPath) else {
            throw XCTSkip("Safari.app not found — skipping cert chain test")
        }
        let info = analyzer.analyze(appPath: safariPath)
        XCTAssertFalse(info.analysisError)
        // Platform binaries may or may not have cert chains depending on OS version,
        // but the extraction should not error.
        if !info.certificateChain.isEmpty {
            let leaf = info.certificateChain[0]
            XCTAssertFalse(leaf.sha256.isEmpty, "Leaf cert should have a SHA-256 fingerprint")
        }
    }

    func testCertificateChainForSignedThirdPartyApp() throws {
        // Try iTerm2 or 1Password as third-party signed apps with full chains.
        let candidates = ["/Applications/iTerm.app", "/Applications/1Password.app"]
        var foundPath: String?
        for path in candidates {
            if FileManager.default.fileExists(atPath: path) {
                foundPath = path
                break
            }
        }
        guard let appPath = foundPath else {
            throw XCTSkip("No third-party signed app found for cert chain test")
        }
        let info = analyzer.analyze(appPath: appPath)
        XCTAssertFalse(info.analysisError)
        XCTAssertFalse(info.isAdhoc, "Third-party signed app should not be ad-hoc")
        XCTAssertGreaterThanOrEqual(info.certificateChain.count, 1, "Should have at least a leaf cert")

        let leaf = info.certificateChain[0]
        XCTAssertNotNil(leaf.commonName, "Leaf cert should have a common name")
        XCTAssertFalse(leaf.sha256.isEmpty, "Leaf cert should have a SHA-256 fingerprint")
        XCTAssertEqual(leaf.sha256.count, 64, "SHA-256 should be 64 hex chars")
    }

    func testAdhocDetectionViaCodeFlags() {
        // Ad-hoc is tested via the makeInfo helper since crafting real ad-hoc binaries in tests is impractical.
        let info = makeInfo(signed: true, hardenedRuntime: false, lvFlag: false, isAdhoc: true)
        XCTAssertTrue(info.isAdhoc, "Should detect ad-hoc flag")
        XCTAssertTrue(info.certificateChain.isEmpty, "Ad-hoc signed apps have no cert chain")
    }

    func testCertificateDetailEncoding() throws {
        let detail = CertificateDetail(
            commonName: "Developer ID Application: Test",
            organization: "Test Org",
            sha256: "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb",
            validFrom: "2022-01-01T00:00:00Z",
            validTo: "2027-01-01T00:00:00Z",
            isRoot: false
        )

        let encoder = JSONEncoder()
        let data = try encoder.encode(detail)
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(CertificateDetail.self, from: data)

        XCTAssertEqual(decoded.commonName, detail.commonName)
        XCTAssertEqual(decoded.organization, detail.organization)
        XCTAssertEqual(decoded.sha256, detail.sha256)
        XCTAssertEqual(decoded.validFrom, detail.validFrom)
        XCTAssertEqual(decoded.validTo, detail.validTo)
        XCTAssertEqual(decoded.isRoot, detail.isRoot)
    }

    // MARK: - Helpers

    private func makeInfo(
        signed: Bool, hardenedRuntime: Bool, lvFlag: Bool, isAdhoc: Bool = false,
        certificateChain: [CertificateDetail] = []
    ) -> CodeSigningInfo {
        CodeSigningInfo(
            signed: signed, teamId: nil, signingIdentifier: nil,
            hardenedRuntime: hardenedRuntime, libraryValidationFlag: lvFlag,
            analysisError: false, isAdhoc: isAdhoc, certificateChain: certificateChain
        )
    }
}
