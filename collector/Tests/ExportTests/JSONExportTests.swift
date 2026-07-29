import XCTest
import Foundation
import Darwin
@testable import Export
@testable import Models

final class JSONExportTests: XCTestCase {

    // MARK: - Helpers

    private func makeSampleApplication() -> Application {
        let entitlement = EntitlementInfo(
            name: "com.apple.security.cs.allow-dyld-environment-variables",
            isPrivate: false,
            category: "injection",
            isSecurityCritical: true
        )
        return Application(
            identity: Application.Identity(
                name: "TestApp",
                bundleId: "com.example.testapp",
                path: "/Applications/TestApp.app",
                version: "1.0"
            ),
            flags: Application.Flags(isElectron: false, isSystem: false),
            signing: Application.Signing(
                teamId: "TEAM123",
                hardenedRuntime: false,
                libraryValidation: false,
                signed: true
            ),
            entitlementState: Application.EntitlementState(
                entitlements: [entitlement],
                injectionMethods: [.missingLibraryValidation]
            )
        )
    }

    private func makeSampleTCCGrant() -> TCCGrant {
        TCCGrant(
            service: "kTCCServiceSystemPolicyAllFiles",
            displayName: "Full Disk Access",
            client: "com.example.testapp",
            clientType: 0,
            authValue: 2,
            authReason: 2,
            scope: "user",
            lastModified: 1710748800
        )
    }

    private func makeSampleScanResult() -> ScanResult {
        return ScanResult(
            metadata: ScanResult.Metadata(
                scanId: "test-scan-001",
                timestamp: "2026-03-18T10:00:00Z",
                hostname: "test-mac",
                macosVersion: "macOS 14.5",
                collectorVersion: "0.1.0"
            ),
            elevation: ElevationInfo(isRoot: false, hasFda: false),
            collections: ScanResult.Collections(
                core: ScanResult.CoreCollections(
                    applications: [makeSampleApplication()],
                    tccGrants: [makeSampleTCCGrant()]
                )
            ),
            errors: []
        )
    }

    // MARK: - Encoding tests

    func testEncodeProducesValidJSON() throws {
        let exporter = JSONExporter()
        let result = makeSampleScanResult()
        let data = try exporter.encode(result)
        XCTAssertFalse(data.isEmpty, "Encoded JSON data must not be empty")
        let json = try JSONSerialization.jsonObject(with: data, options: [])
        XCTAssertNotNil(json, "Encoded data must be valid JSON")
    }

    func testOutputContainsSnakeCaseKeys() throws {
        let exporter = JSONExporter()
        let result = makeSampleScanResult()
        let data = try exporter.encode(result)
        let jsonString = String(data: data, encoding: .utf8)!
        // ScanResult CodingKeys use snake_case
        XCTAssertTrue(jsonString.contains("\"scan_id\""), "Expected snake_case key 'scan_id'")
        XCTAssertTrue(jsonString.contains("\"macos_version\""), "Expected snake_case key 'macos_version'")
        XCTAssertTrue(jsonString.contains("\"tcc_grants\""), "Expected snake_case key 'tcc_grants'")
        XCTAssertTrue(jsonString.contains("\"bundle_id\""), "Expected snake_case key 'bundle_id'")
        XCTAssertTrue(jsonString.contains("\"hardened_runtime\""), "Expected snake_case key 'hardened_runtime'")
        XCTAssertTrue(jsonString.contains("\"injection_methods\""), "Expected snake_case key 'injection_methods'")
    }

    func testSecurityCriticalFieldsEncodeAsJSONBooleans() throws {
        let exporter = JSONExporter()
        let result = makeSampleScanResult()
        let data = try exporter.encode(result)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data, options: []) as? [String: Any])
        let elevation = try XCTUnwrap(json["elevation"] as? [String: Any])
        assertJSONBool(elevation["is_root"], equals: false, at: "elevation.is_root")
        assertJSONBool(elevation["has_fda"], equals: false, at: "elevation.has_fda")

        let applications = try XCTUnwrap(json["applications"] as? [[String: Any]])
        let app = try XCTUnwrap(applications.first)
        assertJSONBool(app["hardened_runtime"], equals: false, at: "applications[0].hardened_runtime")
        assertJSONBool(app["library_validation"], equals: false, at: "applications[0].library_validation")
        assertJSONBool(app["is_electron"], equals: false, at: "applications[0].is_electron")
        assertJSONBool(app["is_system"], equals: false, at: "applications[0].is_system")
        assertJSONBool(app["signed"], equals: true, at: "applications[0].signed")
        assertJSONBool(
            app["code_signing_analysis_error"],
            equals: false,
            at: "applications[0].code_signing_analysis_error"
        )
        assertJSONBool(app["is_sip_protected"], equals: false, at: "applications[0].is_sip_protected")
        assertJSONBool(app["is_sandboxed"], equals: false, at: "applications[0].is_sandboxed")
        assertJSONBool(app["entitlements_available"], equals: true, at: "applications[0].entitlements_available")

        let entitlements = try XCTUnwrap(app["entitlements"] as? [[String: Any]])
        let entitlement = try XCTUnwrap(entitlements.first)
        assertJSONBool(entitlement["is_private"], equals: false, at: "applications[0].entitlements[0].is_private")
        assertJSONBool(
            entitlement["is_security_critical"],
            equals: true,
            at: "applications[0].entitlements[0].is_security_critical"
        )
    }

    // MARK: - Round-trip tests

    func testRoundTripPreservesApplicationData() throws {
        let (original, decoded) = try roundTrippedSampleScanResult()

        XCTAssertEqual(decoded.scanId,           original.scanId)
        XCTAssertEqual(decoded.hostname,         original.hostname)
        XCTAssertEqual(decoded.macosVersion,     original.macosVersion)
        XCTAssertEqual(decoded.collectorVersion, original.collectorVersion)
        XCTAssertEqual(decoded.applications.count, original.applications.count)
        XCTAssertEqual(decoded.tccGrants.count,    original.tccGrants.count)
    }

    func testRoundTripPreservesApplicationProperties() throws {
        let (original, decoded) = try roundTrippedSampleScanResult()

        let origApp = original.applications[0]
        let decApp  = decoded.applications[0]
        XCTAssertEqual(decApp.name,              origApp.name)
        XCTAssertEqual(decApp.bundleId,          origApp.bundleId)
        XCTAssertEqual(decApp.hardenedRuntime,   origApp.hardenedRuntime)
        XCTAssertEqual(decApp.libraryValidation, origApp.libraryValidation)
        XCTAssertEqual(decApp.isElectron,        origApp.isElectron)
        XCTAssertEqual(decApp.signed,            origApp.signed)
        XCTAssertEqual(decApp.entitlements.count, origApp.entitlements.count)
        XCTAssertEqual(decApp.injectionMethods,  origApp.injectionMethods)
    }

    func testRoundTripPreservesTCCGrant() throws {
        let (original, decoded) = try roundTrippedSampleScanResult()

        let origGrant = original.tccGrants[0]
        let decGrant  = decoded.tccGrants[0]
        XCTAssertEqual(decGrant.service,      origGrant.service)
        XCTAssertEqual(decGrant.displayName,  origGrant.displayName)
        XCTAssertEqual(decGrant.client,       origGrant.client)
        XCTAssertEqual(decGrant.authValue,    origGrant.authValue)
        XCTAssertEqual(decGrant.scope,        origGrant.scope)
        XCTAssertEqual(decGrant.lastModified, origGrant.lastModified)
    }

    func testRoundTripPreservesElevationInfo() throws {
        let (original, decoded) = try roundTrippedSampleScanResult()
        XCTAssertEqual(decoded.elevation.isRoot,  original.elevation.isRoot)
        XCTAssertEqual(decoded.elevation.hasFda,  original.elevation.hasFda)
    }

    func testRoundTripEmptyScanResult() throws {
        let exporter = JSONExporter()
        let empty = ScanResult(
            metadata: ScanResult.Metadata(
                scanId: "empty-scan",
                timestamp: "2026-03-18T00:00:00Z",
                hostname: "empty",
                macosVersion: "macOS 14.0",
                collectorVersion: "0.1.0"
            ),
            elevation: ElevationInfo(isRoot: false, hasFda: false),
            errors: []
        )
        let data = try exporter.encode(empty)
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(ScanResult.self, from: data)
        XCTAssertEqual(decoded.scanId,             empty.scanId)
        XCTAssertEqual(decoded.applications.count, 0)
        XCTAssertEqual(decoded.tccGrants.count,    0)
        XCTAssertEqual(decoded.errors.count,       0)
    }

    // MARK: - Write to file

    func testWriteProducesReadableFile() throws {
        let exporter = JSONExporter()
        let result = makeSampleScanResult()
        let tmpPath = NSTemporaryDirectory() + "rootstock-test-export.json"
        defer { try? FileManager.default.removeItem(atPath: tmpPath) }
        try exporter.write(result, to: tmpPath)

        let data = try Data(contentsOf: URL(fileURLWithPath: tmpPath))
        let json = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
        XCTAssertNotNil(json)
        XCTAssertEqual(json?["scan_id"] as? String, "test-scan-001")
    }

    func testWriteRefusesExistingFileWithoutForce() throws {
        let exporter = JSONExporter()
        let tmpPath = try existingOutputPath()
        defer { try? FileManager.default.removeItem(atPath: tmpPath) }

        XCTAssertThrowsError(try exporter.write(makeSampleScanResult(), to: tmpPath)) { error in
            XCTAssertTrue(String(describing: error).contains("outputExists"))
        }
    }

    func testForceReplacesRegularFileWithOwnerOnlyMode() throws {
        let exporter = JSONExporter()
        let tmpPath = try existingOutputPath()
        defer { try? FileManager.default.removeItem(atPath: tmpPath) }
        chmod(tmpPath, 0o644)

        try exporter.write(makeSampleScanResult(), to: tmpPath, force: true)

        let data = try Data(contentsOf: URL(fileURLWithPath: tmpPath))
        XCTAssertNotNil(try JSONSerialization.jsonObject(with: data) as? [String: Any])

        var info = stat()
        XCTAssertEqual(stat(tmpPath, &info), 0)
        XCTAssertEqual(info.st_mode & 0o777, 0o600)
    }

    func testWriteCreatesNewFileWithOwnerOnlyMode() throws {
        let exporter = JSONExporter()
        let tmpPath = NSTemporaryDirectory() + "rootstock-test-\(UUID().uuidString).json"
        defer { try? FileManager.default.removeItem(atPath: tmpPath) }

        try exporter.write(makeSampleScanResult(), to: tmpPath)

        var info = stat()
        XCTAssertEqual(stat(tmpPath, &info), 0)
        XCTAssertEqual(info.st_mode & 0o777, 0o600)
    }

    private func roundTrippedSampleScanResult() throws -> (original: ScanResult, decoded: ScanResult) {
        let original = makeSampleScanResult()
        let data = try JSONExporter().encode(original)
        let decoded = try JSONDecoder().decode(ScanResult.self, from: data)
        return (original, decoded)
    }

    private func existingOutputPath() throws -> String {
        let path = NSTemporaryDirectory() + "rootstock-test-\(UUID().uuidString).json"
        try "existing".write(toFile: path, atomically: false, encoding: .utf8)
        return path
    }

    func testWriteRefusesSymlinkEvenWithForce() throws {
        let exporter = JSONExporter()
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("rootstock-export-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let target = dir.appendingPathComponent("target.json")
        let link = dir.appendingPathComponent("link.json")
        try "existing".write(to: target, atomically: false, encoding: .utf8)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)

        XCTAssertThrowsError(try exporter.write(makeSampleScanResult(), to: link.path, force: true)) { error in
            XCTAssertTrue(String(describing: error).contains("outputIsSymlink"))
        }
        XCTAssertEqual(try String(contentsOf: target), "existing")
    }

    private func assertJSONBool(
        _ value: Any?,
        equals expected: Bool,
        at path: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        guard let value else {
            XCTFail("Missing JSON value at \(path)", file: file, line: line)
            return
        }
        XCTAssertEqual(
            CFGetTypeID(value as AnyObject),
            CFBooleanGetTypeID(),
            "\(path) must encode as a JSON boolean, not a number",
            file: file,
            line: line
        )
        XCTAssertEqual(value as? Bool, expected, file: file, line: line)
    }
}
