import XCTest
@testable import Entitlements
import Models

final class EntitlementTests: XCTestCase {

    // MARK: - EntitlementClassifier tests

    let classifier = EntitlementClassifier()

    func testClassifyTCCEntitlement() {
        let result = classifier.classify(["com.apple.private.tcc.allow": ["kTCCServiceMicrophone"]])
        XCTAssertEqual(result.count, 1)
        XCTAssertEqual(result[0].category, "tcc")
        XCTAssertTrue(result[0].isPrivate)
        XCTAssertTrue(result[0].isSecurityCritical)
    }

    func testClassifyInjectionEntitlements() {
        let keys = [
            "com.apple.security.cs.allow-dyld-environment-variables",
            "com.apple.security.cs.disable-library-validation",
            "com.apple.security.cs.allow-unsigned-executable-memory",
        ]
        for key in keys {
            let result = classifier.classify([key: true])
            XCTAssertEqual(result.first?.category, "injection", "\(key) should be injection")
            XCTAssertTrue(result.first?.isSecurityCritical == true, "\(key) should be security critical")
        }
    }

    func testClassifyPrivilegeEntitlements() {
        let keys = [
            "com.apple.security.get-task-allow",
            "com.apple.security.cs.debugger",
            "com.apple.rootless.install",
        ]
        for key in keys {
            let result = classifier.classify([key: true])
            XCTAssertEqual(result.first?.category, "privilege", "\(key) should be privilege")
            XCTAssertTrue(result.first?.isSecurityCritical == true, "\(key) should be security critical")
        }
    }

    func testClassifySandboxEntitlement() {
        let result = classifier.classify(["com.apple.security.app-sandbox": true])
        XCTAssertEqual(result.first?.category, "sandbox")
        XCTAssertFalse(result.first?.isSecurityCritical == true)
    }

    func testClassifyNetworkEntitlement() {
        let result = classifier.classify(["com.apple.security.network.client": true])
        XCTAssertEqual(result.first?.category, "network")
        XCTAssertFalse(result.first?.isSecurityCritical == true)
    }

    func testClassifyKeychainEntitlement() {
        let result = classifier.classify(["keychain-access-groups": ["group1"]])
        XCTAssertEqual(result.first?.category, "keychain")
    }

    func testClassifyICloudEntitlements() {
        let keys = [
            "com.apple.developer.icloud-container-identifiers",
            "com.apple.developer.icloud-container-environment",
            "com.apple.developer.ubiquity-container-identifiers",
            "com.apple.developer.ubiquity-kvstore-identifier",
            "com.apple.developer.cloudkit-container",
        ]
        for key in keys {
            let result = classifier.classify([key: true])
            XCTAssertEqual(result.first?.category, "icloud", "\(key) should be icloud")
            XCTAssertFalse(result.first?.isSecurityCritical == true, "\(key) should not be security critical")
        }
    }

    func testClassifyOtherEntitlement() {
        let result = classifier.classify(["com.apple.developer.something": true])
        XCTAssertEqual(result.first?.category, "other")
        XCTAssertFalse(result.first?.isSecurityCritical == true)
    }

    func testIsPrivateFlag() {
        let results = classifier.classify([
            "com.apple.private.tcc.allow": true,
            "com.apple.security.app-sandbox": true,
        ])
        let byName = Dictionary(uniqueKeysWithValues: results.map { ($0.name, $0) })
        XCTAssertTrue(byName["com.apple.private.tcc.allow"]?.isPrivate == true)
        XCTAssertFalse(byName["com.apple.security.app-sandbox"]?.isPrivate == true)
    }

    func testEmptyEntitlementsDict() {
        let results = classifier.classify([:])
        XCTAssertTrue(results.isEmpty)
    }

    // MARK: - AppDiscovery tests

    func testDiscoveryFindsAppsInDirectory() throws {
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("test-discovery-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        // Build a minimal fake .app bundle
        let appDir = tempDir.appendingPathComponent("FakeApp.app")
        let contentsDir = appDir.appendingPathComponent("Contents")
        let macosDir = contentsDir.appendingPathComponent("MacOS")
        try FileManager.default.createDirectory(at: macosDir, withIntermediateDirectories: true)

        // Info.plist
        let plist: [String: Any] = [
            "CFBundleIdentifier": "com.test.fakeapp",
            "CFBundleName": "FakeApp",
            "CFBundleShortVersionString": "1.0",
            "CFBundleExecutable": "FakeApp",
        ]
        let plistData = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        try plistData.write(to: contentsDir.appendingPathComponent("Info.plist"))

        // Fake executable (empty file is enough for discovery)
        FileManager.default.createFile(atPath: macosDir.appendingPathComponent("FakeApp").path, contents: nil)

        let discovery = AppDiscovery(additionalDirectories: [tempDir])
        let found = discovery.discover()

        XCTAssertTrue(found.contains { $0.bundleId == "com.test.fakeapp" }, "Should discover fake app")
        let app = found.first { $0.bundleId == "com.test.fakeapp" }
        XCTAssertEqual(app?.name, "FakeApp")
        XCTAssertEqual(app?.version, "1.0")
    }

    func testDiscoverySkipsBundleWithoutInfoPlist() throws {
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("test-discovery-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        // Create .app with no Info.plist
        let appDir = tempDir.appendingPathComponent("Broken.app")
        try FileManager.default.createDirectory(
            at: appDir.appendingPathComponent("Contents/MacOS"),
            withIntermediateDirectories: true
        )

        let discovery = AppDiscovery(additionalDirectories: [tempDir])
        let found = discovery.discover()
        XCTAssertFalse(found.contains { $0.path == appDir.path }, "Broken app should be skipped")
    }

    func testElectronDetection() throws {
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("test-electron-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let appDir = tempDir.appendingPathComponent("ElectronApp.app")
        let contentsDir = appDir.appendingPathComponent("Contents")
        let macosDir = contentsDir.appendingPathComponent("MacOS")
        let electronFramework = contentsDir
            .appendingPathComponent("Frameworks")
            .appendingPathComponent("Electron Framework.framework")
        try FileManager.default.createDirectory(at: macosDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: electronFramework, withIntermediateDirectories: true)

        let plist: [String: Any] = [
            "CFBundleIdentifier": "com.test.electron",
            "CFBundleName": "ElectronApp",
            "CFBundleExecutable": "ElectronApp",
        ]
        let plistData = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        try plistData.write(to: contentsDir.appendingPathComponent("Info.plist"))
        FileManager.default.createFile(atPath: macosDir.appendingPathComponent("ElectronApp").path, contents: nil)

        let discovery = AppDiscovery(additionalDirectories: [tempDir])
        let found = discovery.discover()

        let app = found.first { $0.bundleId == "com.test.electron" }
        XCTAssertNotNil(app, "Should discover Electron app")
        XCTAssertTrue(app?.isElectron == true, "Should detect as Electron")
    }

    // MARK: - Integration test: real app entitlement extraction

    func testExtractFromRealApp() throws {
        // Terminal.app always exists on macOS — use it to verify extraction works.
        let terminalExec = "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"
        guard FileManager.default.fileExists(atPath: terminalExec) else {
            throw XCTSkip("Terminal.app not found — skipping integration test")
        }

        let extractor = EntitlementExtractor()
        let result = extractor.extract(from: URL(fileURLWithPath: terminalExec))

        // Terminal.app must have at least some entitlements
        XCTAssertFalse(result.isEmpty, "Terminal.app should have entitlements")
        // On macOS 26.3, Terminal.app has TCC private entitlements (not sandboxed)
        XCTAssertNotNil(result["com.apple.private.tcc.allow-prompting"], "Terminal.app should have TCC prompting entitlement")
    }
}
