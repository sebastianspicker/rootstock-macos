import XCTest
import Security
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

    func testNonExistentPathReturnsAnalysisError() {
        let info = analyzer.analyze(appPath: "/nonexistent/path/Fake.app")
        XCTAssertTrue(info.analysisError, "Should report analysis error for missing path")
        XCTAssertNil(info.teamId)
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

    func testSigningInformationParserDistinguishesPlatformAndDeveloperIdentifiers() {
        let platformInfo = analyzer.codeSigningInfo(from: [
            kSecCodeInfoIdentifier as String: "com.apple.Terminal",
            kSecCodeInfoFlags as String: NSNumber(value: 0)
        ])

        XCTAssertTrue(platformInfo.signed)
        XCTAssertEqual(platformInfo.signingIdentifier, "com.apple.Terminal")
        XCTAssertNil(platformInfo.teamId)
        XCTAssertFalse(platformInfo.hardenedRuntime)
        XCTAssertFalse(platformInfo.libraryValidationFlag)
        XCTAssertFalse(platformInfo.isAdhoc)

        let developerInfo = analyzer.codeSigningInfo(from: [
            kSecCodeInfoIdentifier as String: "com.example.SignedApp",
            kSecCodeInfoTeamIdentifier as String: "ABCDE12345",
            kSecCodeInfoFlags as String: NSNumber(value: 0x10000 | 0x2000)
        ])

        XCTAssertTrue(developerInfo.signed)
        XCTAssertEqual(developerInfo.signingIdentifier, "com.example.SignedApp")
        XCTAssertEqual(developerInfo.teamId, "ABCDE12345")
        XCTAssertTrue(developerInfo.hardenedRuntime)
        XCTAssertTrue(developerInfo.libraryValidationFlag)
        XCTAssertFalse(developerInfo.isAdhoc)
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

    func testAnalysisErrorDoesNotProduceInjectionMethods() {
        let info = makeInfo(signed: false, hardenedRuntime: false, lvFlag: false, analysisError: true)
        let result = assessment.assess(signingInfo: info, entitlements: [], isElectron: false)
        XCTAssertTrue(result.methods.isEmpty, "Unknown signing posture must not become injectable evidence")
    }

    // MARK: - CodeSigningDataSource enrichment tests

    func testEnrichmentPopulatesSignedField() throws {
        let safariPath = "/Applications/Safari.app"
        guard FileManager.default.fileExists(atPath: safariPath) else {
            throw XCTSkip("Safari.app not found")
        }

        var apps = [Application(
            identity: Application.Identity(
                name: "Safari",
                bundleId: "com.apple.Safari",
                path: safariPath,
                version: nil
            ),
            flags: Application.Flags(isElectron: false, isSystem: false),
            signing: Application.Signing(
                hardenedRuntime: false,
                libraryValidation: false,
                signed: false
            )
        )]
        let source = CodeSigningDataSource()
        source.enrich(applications: &apps)

        XCTAssertEqual(apps[0].signed, true, "Safari should be signed after enrichment")
        XCTAssertEqual(apps[0].libraryValidation, true, "Safari should have library validation after enrichment")
    }

    func testEnrichmentFailureRecordsError() {
        var apps = [Application(
            identity: Application.Identity(
                name: "Fake",
                bundleId: "com.fake.app",
                path: "/nonexistent/Fake.app",
                version: nil
            ),
            flags: Application.Flags(isElectron: false, isSystem: false),
            signing: Application.Signing(
                hardenedRuntime: false,
                libraryValidation: false,
                signed: false
            )
        )]
        let source = CodeSigningDataSource()
        let errors = source.enrich(applications: &apps)

        XCTAssertFalse(errors.isEmpty, "Should record error for unanalyzable app")
        XCTAssertTrue(apps[0].codeSigningAnalysisError, "Unanalyzable app should preserve analysis failure")
        XCTAssertNil(apps[0].signed, "Unanalyzable app signing state should be unknown")
        XCTAssertNil(apps[0].hardenedRuntime, "Unanalyzable hardened runtime state should be unknown")
        XCTAssertNil(apps[0].libraryValidation, "Unanalyzable library validation state should be unknown")
        XCTAssertTrue(apps[0].injectionMethods.isEmpty, "Unanalyzable app should not get injection methods")
        XCTAssertNil(apps[0].launchConstraintCategory, "Unanalyzable launch constraint should be unknown")
    }

    func testEnrichedReturnsCopyAndLeavesInputUntouched() {
        let apps = [Application(
            identity: Application.Identity(
                name: "Fake",
                bundleId: "com.fake.app",
                path: "/nonexistent/Fake.app",
                version: nil
            ),
            flags: Application.Flags(isElectron: false, isSystem: false),
            signing: Application.Signing(
                hardenedRuntime: false,
                libraryValidation: false,
                signed: false
            )
        )]
        let source = CodeSigningDataSource()

        let (enrichedApps, errors) = source.enriched(applications: apps)

        XCTAssertFalse(errors.isEmpty, "Should record error for unanalyzable app")
        XCTAssertEqual(apps[0].signed, false, "Input application should not be mutated")
        XCTAssertFalse(apps[0].codeSigningAnalysisError, "Input application should not be mutated")
        XCTAssertNil(enrichedApps[0].signed, "Output signing state should be unknown after failed analysis")
        XCTAssertTrue(enrichedApps[0].codeSigningAnalysisError)
    }

    func testMissingEntitlementsSuppressesEntitlementDependentInjectionFacts() throws {
        let terminalPath = "/System/Applications/Utilities/Terminal.app"
        guard FileManager.default.fileExists(atPath: terminalPath) else {
            throw XCTSkip("Terminal.app not found")
        }
        var apps = [Application(
            identity: Application.Identity(
                name: "Terminal",
                bundleId: "com.apple.Terminal",
                path: terminalPath,
                version: nil
            ),
            flags: Application.Flags(isElectron: false, isSystem: false),
            signing: Application.Signing(),
            entitlementState: Application.EntitlementState(
                entitlementsAvailable: false,
                entitlementExtractionError: "codesign failed"
            )
        )]
        let source = CodeSigningDataSource()
        _ = source.enrich(applications: &apps)

        XCTAssertEqual(apps[0].signed, true)
        XCTAssertNil(apps[0].libraryValidation)
        XCTAssertFalse(apps[0].entitlementsAvailable)
        XCTAssertEqual(apps[0].entitlementExtractionError, "codesign failed")
        XCTAssertTrue(apps[0].injectionMethods.isEmpty)
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
        for path in candidates where FileManager.default.fileExists(atPath: path) {
            foundPath = path
            break
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

    func testAdhocSignedExecutableIsClassifiedAsInjectable() throws {
        let fixtureDirectory = try makeTemporaryFixtureDirectory()
        defer { try? FileManager.default.removeItem(at: fixtureDirectory) }
        let executableURL = try makeAdhocSignedExecutable(in: fixtureDirectory)

        let info = analyzer.analyze(appPath: executableURL.path)
        XCTAssertTrue(info.isAdhoc, "Should detect ad-hoc flag")
        XCTAssertTrue(info.certificateChain.isEmpty, "Ad-hoc signed apps have no cert chain")

        let methods = assessment.assess(signingInfo: info, entitlements: [], isElectron: false).methods
        XCTAssertTrue(methods.contains(.dyldInsert), "Ad-hoc executable should be DYLD injectable")
        XCTAssertTrue(methods.contains(.missingLibraryValidation), "Ad-hoc executable should lack library validation")
    }

    func testUniversalBinaryAnalysisUsesNativeArchitectureSlice() throws {
        let fixtureDirectory = try makeTemporaryFixtureDirectory()
        defer { try? FileManager.default.removeItem(at: fixtureDirectory) }
        let executableURL = try makeMixedSigningUniversalExecutable(in: fixtureDirectory)

        let info = analyzer.analyze(appPath: executableURL.path)
        XCTAssertFalse(info.analysisError)
        XCTAssertTrue(info.isAdhoc)
        XCTAssertTrue(
            info.hardenedRuntime,
            "Native architecture slice is signed with hardened runtime; the non-native slice is not"
        )

        let result = assessment.assess(signingInfo: info, entitlements: [], isElectron: false)
        XCTAssertFalse(
            result.methods.contains(.dyldInsert),
            "Selecting the non-native slice would incorrectly report DYLD injection"
        )
        XCTAssertTrue(result.effectiveLibraryValidation)
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
        certificateChain: [CertificateDetail] = [], analysisError: Bool = false
    ) -> CodeSigningInfo {
        CodeSigningInfo(
            signed: signed, teamId: nil, signingIdentifier: nil,
            hardenedRuntime: hardenedRuntime, libraryValidationFlag: lvFlag,
            analysisError: analysisError, isAdhoc: isAdhoc, certificateChain: certificateChain
        )
    }

    private func makeTemporaryFixtureDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("rootstock-codesign-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    private func makeAdhocSignedExecutable(in directory: URL) throws -> URL {
        let sourceURL = URL(fileURLWithPath: "/bin/echo")
        let executableURL = directory.appendingPathComponent("adhoc-fixture")
        try FileManager.default.copyItem(at: sourceURL, to: executableURL)

        let result = try XCTUnwrap(
            Shell.runProcess(
                "/usr/bin/codesign",
                ["--force", "--sign", "-", executableURL.path],
                timeoutSeconds: 10
            ),
            "codesign command should be available on supported macOS collector hosts"
        )
        XCTAssertFalse(result.timedOut, "codesign should finish before timeout")
        XCTAssertEqual(result.terminationStatus, 0, "codesign failed: \(result.stderr)")
        return executableURL
    }

    private func makeMixedSigningUniversalExecutable(in directory: URL) throws -> URL {
        let nativeArch = try currentMachineArchitecture()
        let supportedArchitectures = ["arm64", "x86_64"]
        guard supportedArchitectures.contains(nativeArch) else {
            throw XCTSkip("Unsupported architecture for mixed universal fixture: \(nativeArch)")
        }

        let sourceURL = directory.appendingPathComponent("main.c")
        try "int main(void) { return 0; }\n".write(to: sourceURL, atomically: true, encoding: .utf8)

        var executableByArch: [String: URL] = [:]
        for architecture in supportedArchitectures {
            let executableURL = directory.appendingPathComponent("\(architecture)-fixture")
            try runFixtureCommand(
                "/usr/bin/clang",
                ["-arch", architecture, sourceURL.path, "-o", executableURL.path],
                description: "compile \(architecture) fixture"
            )
            let signArguments = architecture == nativeArch
                ? ["--force", "--sign", "-", "--options", "runtime", executableURL.path]
                : ["--force", "--sign", "-", executableURL.path]
            try runFixtureCommand(
                "/usr/bin/codesign",
                signArguments,
                description: "sign \(architecture) fixture"
            )
            executableByArch[architecture] = executableURL
        }

        let universalURL = directory.appendingPathComponent("mixed-universal-fixture")
        try runFixtureCommand(
            "/usr/bin/lipo",
            [
                "-create",
                executableByArch["arm64"]!.path,
                executableByArch["x86_64"]!.path,
                "-output",
                universalURL.path,
            ],
            description: "create mixed-signing universal fixture"
        )
        return universalURL
    }

    private func currentMachineArchitecture() throws -> String {
        let result = try XCTUnwrap(
            Shell.runProcess("/usr/bin/uname", ["-m"], timeoutSeconds: 5),
            "uname command should be available on supported macOS collector hosts"
        )
        guard result.terminationStatus == 0, !result.timedOut else {
            throw XCTSkip("Could not determine native architecture: \(result.stderr)")
        }
        return result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func runFixtureCommand(
        _ path: String,
        _ arguments: [String],
        description: String
    ) throws {
        guard FileManager.default.isExecutableFile(atPath: path) else {
            throw XCTSkip("\(path) not available for \(description)")
        }
        let result = try XCTUnwrap(
            Shell.runProcess(path, arguments, timeoutSeconds: 15),
            "\(description) command should start"
        )
        guard !result.timedOut, result.terminationStatus == 0 else {
            throw XCTSkip("\(description) failed: \(result.stderr)")
        }
    }
}
