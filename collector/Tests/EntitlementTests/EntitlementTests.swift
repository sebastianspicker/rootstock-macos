import XCTest
import Darwin
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
        let found = discovery.discover().applications

        XCTAssertTrue(found.contains { $0.bundleId == "com.test.fakeapp" }, "Should discover fake app")
        let app = found.first { $0.bundleId == "com.test.fakeapp" }
        XCTAssertEqual(app?.name, "FakeApp")
        XCTAssertEqual(app?.version, "1.0")
    }

    func testDiscoveryFindsAppsExactlyOneNestedDirectoryDeep() throws {
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("nested-discovery-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        try createFakeApplication(
            at: tempDir.appendingPathComponent("Direct.app"),
            bundleIdentifier: "com.test.direct"
        )
        try createFakeApplication(
            at: tempDir.appendingPathComponent("Category/Nested.app"),
            bundleIdentifier: "com.test.nested"
        )
        try createFakeApplication(
            at: tempDir.appendingPathComponent("Category/Deeper/TooDeep.app"),
            bundleIdentifier: "com.test.too-deep"
        )

        let result = AppDiscovery(directories: [tempDir], limits: .default).discover()
        let identifiers = Set(result.applications.map(\.bundleId))

        XCTAssertTrue(identifiers.contains("com.test.direct"))
        XCTAssertTrue(identifiers.contains("com.test.nested"))
        XCTAssertFalse(identifiers.contains("com.test.too-deep"))
    }

    func testDiscoveryStopsAtConfiguredEntryLimit() throws {
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("entry-limit-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        for index in 0..<3 {
            FileManager.default.createFile(
                atPath: tempDir.appendingPathComponent("placeholder-\(index)").path,
                contents: Data()
            )
        }

        let result = AppDiscovery(
            directories: [tempDir],
            limits: AppDiscoveryLimits(maximumEntries: 2, maximumInfoPlistBytes: 1024)
        ).discover()

        XCTAssertTrue(result.errors.contains { $0.message.contains("2-entry scan limit") })
    }

    func testDiscoveryRejectsInfoPlistBeyondByteBudget() throws {
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("plist-budget-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let result = try oversizedPlistDiscoveryResult(in: tempDir, named: "Large")

        XCTAssertTrue(result.applications.isEmpty)
        XCTAssertTrue(result.errors.contains { $0.message.contains("discovery budget") })
    }

    func testOversizedPlistOrderingDoesNotStarveLaterValidApplications() throws {
        let oversizedFirst = try discoverValidApplication(oversizedFirst: true)
        let oversizedLast = try discoverValidApplication(oversizedFirst: false)

        XCTAssertEqual(oversizedFirst.applications.map(\.bundleId), ["com.test.valid"])
        XCTAssertEqual(oversizedLast.applications.map(\.bundleId), ["com.test.valid"])
        XCTAssertEqual(
            oversizedFirst.applications.map(\.bundleId),
            oversizedLast.applications.map(\.bundleId)
        )
        XCTAssertTrue(
            oversizedFirst.errors.contains { $0.message.contains("per-file discovery budget") }
        )
        XCTAssertTrue(
            oversizedLast.errors.contains { $0.message.contains("per-file discovery budget") }
        )
    }

    func testAggregateBudgetAppliesOnlyAfterPerFileAcceptance() throws {
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("aggregate-plist-budget-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let firstApp = tempDir.appendingPathComponent("A-First.app")
        let secondApp = tempDir.appendingPathComponent("B-Second.app")
        try createFakeApplication(at: firstApp, bundleIdentifier: "com.test.first")
        try createFakeApplication(at: secondApp, bundleIdentifier: "com.test.second")

        let firstBytes = try Data(
            contentsOf: firstApp.appendingPathComponent("Contents/Info.plist")
        ).count
        let secondBytes = try Data(
            contentsOf: secondApp.appendingPathComponent("Contents/Info.plist")
        ).count
        let result = AppDiscovery(
            directories: [tempDir],
            limits: AppDiscoveryLimits(
                maximumEntries: 20,
                maximumInfoPlistBytes: firstBytes + secondBytes - 1,
                maximumInfoPlistBytesPerFile: max(firstBytes, secondBytes)
            )
        ).discover()

        XCTAssertEqual(result.applications.map(\.bundleId), ["com.test.first"])
        XCTAssertTrue(
            result.errors.contains { $0.message.contains("aggregate") }
        )
    }

    func testDiscoveryRejectsInfoPlistFifoWithoutBlocking() throws {
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("plist-fifo-\(UUID().uuidString)")
        let directories = try makeApplicationDirectories(at: tempDir, named: "Fifo")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let plistURL = directories.contents.appendingPathComponent("Info.plist")
        let fifoResult = plistURL.path.withCString { Darwin.mkfifo($0, mode_t(0o600)) }
        XCTAssertEqual(fifoResult, 0)
        FileManager.default.createFile(
            atPath: directories.macos.appendingPathComponent("Fifo").path,
            contents: Data()
        )

        let start = Date()
        let result = AppDiscovery(directories: [tempDir], limits: .default).discover()

        XCTAssertLessThan(Date().timeIntervalSince(start), 1.0)
        XCTAssertTrue(result.applications.isEmpty)
        XCTAssertTrue(result.errors.contains { $0.message.contains("not a regular file") })
    }

    func testDiscoveryBoundsSparseInfoPlistReadToRemainingBudget() throws {
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("plist-sparse-\(UUID().uuidString)")
        let appDir = tempDir.appendingPathComponent("Sparse.app")
        let contentsDir = appDir.appendingPathComponent("Contents")
        let macosDir = contentsDir.appendingPathComponent("MacOS")
        try FileManager.default.createDirectory(at: macosDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let plistURL = contentsDir.appendingPathComponent("Info.plist")
        FileManager.default.createFile(atPath: plistURL.path, contents: Data())
        let handle = try FileHandle(forWritingTo: plistURL)
        try handle.truncate(atOffset: 512 * 1024 * 1024)
        try handle.close()
        FileManager.default.createFile(
            atPath: macosDir.appendingPathComponent("Sparse").path,
            contents: Data()
        )

        let result = AppDiscovery(
            directories: [tempDir],
            limits: AppDiscoveryLimits(maximumEntries: 10, maximumInfoPlistBytes: 1024)
        ).discover()

        XCTAssertTrue(result.applications.isEmpty)
        XCTAssertTrue(result.errors.contains { $0.message.contains("discovery budget") })
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
        let result = discovery.discover()
        let found = result.applications
        XCTAssertFalse(found.contains { $0.path == appDir.path }, "Broken app should be skipped")
        XCTAssertTrue(
            result.errors.contains { $0.message.contains("Info.plist missing or unreadable") },
            "Skipped app should produce a discovery diagnostic"
        )
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
        let found = discovery.discover().applications

        let app = found.first { $0.bundleId == "com.test.electron" }
        XCTAssertNotNil(app, "Should discover Electron app")
        XCTAssertTrue(app?.isElectron == true, "Should detect as Electron")
    }

    func testDiscoveryReportsMalformedInfoPlist() throws {
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("test-discovery-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let directories = try makeApplicationDirectories(at: tempDir, named: "Broken")
        try Data("not a plist".utf8).write(to: directories.contents.appendingPathComponent("Info.plist"))

        let result = AppDiscovery(additionalDirectories: [tempDir]).discover()
        assertDiscoveryRejection(result, for: directories.app, containing: "malformed Info.plist")
    }

    func testDiscoveryReportsMissingExecutable() throws {
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("test-discovery-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let appDir = tempDir.appendingPathComponent("MissingExecutable.app")
        let contentsDir = appDir.appendingPathComponent("Contents")
        try FileManager.default.createDirectory(
            at: contentsDir.appendingPathComponent("MacOS"),
            withIntermediateDirectories: true
        )
        let plist: [String: Any] = [
            "CFBundleIdentifier": "com.test.missing-exec",
            "CFBundleName": "MissingExecutable",
            "CFBundleExecutable": "MissingExecutable",
        ]
        let plistData = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        try plistData.write(to: contentsDir.appendingPathComponent("Info.plist"))

        let result = AppDiscovery(additionalDirectories: [tempDir]).discover()

        assertDiscoveryRejection(result, for: appDir, containing: "executable missing")
    }

    private func createFakeApplication(at appURL: URL, bundleIdentifier: String) throws {
        let name = appURL.deletingPathExtension().lastPathComponent
        let contentsURL = appURL.appendingPathComponent("Contents")
        let macOSURL = contentsURL.appendingPathComponent("MacOS")
        try FileManager.default.createDirectory(at: macOSURL, withIntermediateDirectories: true)
        let plist: [String: Any] = [
            "CFBundleIdentifier": bundleIdentifier,
            "CFBundleName": name,
            "CFBundleExecutable": name,
        ]
        let data = try PropertyListSerialization.data(
            fromPropertyList: plist,
            format: .xml,
            options: 0
        )
        try data.write(to: contentsURL.appendingPathComponent("Info.plist"))
        FileManager.default.createFile(
            atPath: macOSURL.appendingPathComponent(name).path,
            contents: Data()
        )
    }

    private struct ApplicationDirectories {
        let app: URL
        let contents: URL
        let macos: URL
    }

    private func makeApplicationDirectories(at root: URL, named name: String) throws -> ApplicationDirectories {
        let app = root.appendingPathComponent("\(name).app")
        let contents = app.appendingPathComponent("Contents")
        let macos = contents.appendingPathComponent("MacOS")
        try FileManager.default.createDirectory(at: macos, withIntermediateDirectories: true)
        return ApplicationDirectories(app: app, contents: contents, macos: macos)
    }

    private func oversizedPlistDiscoveryResult(in directory: URL, named name: String) throws -> AppDiscoveryResult {
        let directories = try makeApplicationDirectories(at: directory, named: name)
        try Data(repeating: 0, count: 1025).write(
            to: directories.contents.appendingPathComponent("Info.plist")
        )
        FileManager.default.createFile(
            atPath: directories.macos.appendingPathComponent(name).path,
            contents: Data()
        )
        return AppDiscovery(
            directories: [directory],
            limits: .init(maximumEntries: 10, maximumInfoPlistBytes: 1024)
        ).discover()
    }

    private func assertDiscoveryRejection(
        _ result: AppDiscoveryResult,
        for app: URL,
        containing message: String
    ) {
        XCTAssertFalse(result.applications.contains { $0.path == app.path })
        XCTAssertTrue(result.errors.contains { $0.message.contains(message) })
    }

    private func discoverValidApplication(oversizedFirst: Bool) throws -> AppDiscoveryResult {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("oversized-order-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }

        let oversizedName = oversizedFirst ? "A-Oversized" : "Z-Oversized"
        let validName = oversizedFirst ? "Z-Valid" : "A-Valid"
        try createFakeApplication(
            at: root.appendingPathComponent("\(oversizedName).app"),
            bundleIdentifier: "com.test.oversized"
        )
        try Data(repeating: 0, count: 1025).write(
            to: root.appendingPathComponent("\(oversizedName).app/Contents/Info.plist")
        )
        try createFakeApplication(
            at: root.appendingPathComponent("\(validName).app"),
            bundleIdentifier: "com.test.valid"
        )
        return AppDiscovery(
            directories: [root],
            limits: AppDiscoveryLimits(
                maximumEntries: 20,
                maximumInfoPlistBytes: 1024,
                maximumInfoPlistBytesPerFile: 512
            )
        ).discover()
    }

    // MARK: - Integration test: real app entitlement extraction

    func testExtractFromRealApp() throws {
        // Terminal.app always exists on macOS - use it to verify extraction works.
        let terminalExec = "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"
        guard FileManager.default.fileExists(atPath: terminalExec) else {
            throw XCTSkip("Terminal.app not found - skipping integration test")
        }

        let extractor = EntitlementExtractor()
        let result = extractor.extract(from: URL(fileURLWithPath: terminalExec))

        // Terminal.app must have at least some entitlements
        XCTAssertTrue(result.available, "Terminal.app entitlement extraction should be available")
        XCTAssertFalse(result.entitlements.isEmpty, "Terminal.app should have entitlements")
        // On macOS 26.3, Terminal.app has TCC private entitlements (not sandboxed)
        XCTAssertNotNil(
            result.entitlements["com.apple.private.tcc.allow-prompting"],
            "Terminal.app should have TCC prompting entitlement"
        )
    }

    func testExtractorMissingExecutableReportsUnavailable() {
        let extractor = EntitlementExtractor()
        let result = extractor.extract(from: URL(fileURLWithPath: "/nonexistent/Fake.app/Contents/MacOS/Fake"))

        XCTAssertFalse(result.available, "Missing executable should not look like a valid empty entitlement set")
        XCTAssertTrue(result.entitlements.isEmpty)
        XCTAssertNotNil(result.errorMessage)
    }
}
