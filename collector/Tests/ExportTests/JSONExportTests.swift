import XCTest
import Foundation
@testable import Export
@testable import Models

final class JSONExportTests: XCTestCase {

    // MARK: - Helpers

    private func makeSampleScanResult() -> ScanResult {
        let entitlement = EntitlementInfo(
            name: "com.apple.security.cs.allow-dyld-environment-variables",
            isPrivate: false,
            category: "injection",
            isSecurityCritical: true
        )
        let app = Application(
            name: "TestApp",
            bundleId: "com.example.testapp",
            path: "/Applications/TestApp.app",
            version: "1.0",
            teamId: "TEAM123",
            hardenedRuntime: false,
            libraryValidation: false,
            isElectron: false,
            isSystem: false,
            signed: true,
            entitlements: [entitlement],
            injectionMethods: [.missingLibraryValidation]
        )
        let grant = TCCGrant(
            service: "kTCCServiceSystemPolicyAllFiles",
            displayName: "Full Disk Access",
            client: "com.example.testapp",
            clientType: 0,
            authValue: 2,
            authReason: 2,
            scope: "user",
            lastModified: 1710748800
        )
        return ScanResult(
            scanId: "test-scan-001",
            timestamp: "2026-03-18T10:00:00Z",
            hostname: "test-mac",
            macosVersion: "macOS 14.5",
            collectorVersion: "0.1.0",
            elevation: ElevationInfo(isRoot: false, hasFda: false),
            applications: [app],
            tccGrants: [grant],
            xpcServices: [],
            keychainAcls: [],
            mdmProfiles: [],
            launchItems: [],
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

    // MARK: - Round-trip tests

    func testRoundTripPreservesApplicationData() throws {
        let exporter = JSONExporter()
        let original = makeSampleScanResult()
        let data = try exporter.encode(original)
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(ScanResult.self, from: data)

        XCTAssertEqual(decoded.scanId,           original.scanId)
        XCTAssertEqual(decoded.hostname,         original.hostname)
        XCTAssertEqual(decoded.macosVersion,     original.macosVersion)
        XCTAssertEqual(decoded.collectorVersion, original.collectorVersion)
        XCTAssertEqual(decoded.applications.count, original.applications.count)
        XCTAssertEqual(decoded.tccGrants.count,    original.tccGrants.count)
    }

    func testRoundTripPreservesApplicationProperties() throws {
        let exporter = JSONExporter()
        let original = makeSampleScanResult()
        let data = try exporter.encode(original)
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(ScanResult.self, from: data)

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
        let exporter = JSONExporter()
        let original = makeSampleScanResult()
        let data = try exporter.encode(original)
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(ScanResult.self, from: data)

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
        let exporter = JSONExporter()
        let original = makeSampleScanResult()
        let data = try exporter.encode(original)
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(ScanResult.self, from: data)
        XCTAssertEqual(decoded.elevation.isRoot,  original.elevation.isRoot)
        XCTAssertEqual(decoded.elevation.hasFda,  original.elevation.hasFda)
    }

    func testRoundTripEmptyScanResult() throws {
        let exporter = JSONExporter()
        let empty = ScanResult(
            scanId: "empty-scan",
            timestamp: "2026-03-18T00:00:00Z",
            hostname: "empty",
            macosVersion: "macOS 14.0",
            collectorVersion: "0.1.0",
            elevation: ElevationInfo(isRoot: false, hasFda: false),
            applications: [],
            tccGrants: [],
            xpcServices: [],
            keychainAcls: [],
            mdmProfiles: [],
            launchItems: [],
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
}
