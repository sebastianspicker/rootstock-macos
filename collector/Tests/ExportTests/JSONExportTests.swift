import Testing
import Foundation
import Darwin
@testable import Export
@testable import Models

@Suite struct JSONExportTests {

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

    @Test func encodeProducesValidJSON() throws {
        let exporter = JSONExporter()
        let result = makeSampleScanResult()
        let data = try exporter.encode(result)
        #expect(!data.isEmpty, "Encoded JSON data must not be empty")
        #expect(throws: Never.self, "Encoded data must be valid JSON") {
            try JSONSerialization.jsonObject(with: data, options: [])
        }
    }

    @Test func outputContainsSnakeCaseKeys() throws {
        let exporter = JSONExporter()
        let result = makeSampleScanResult()
        let data = try exporter.encode(result)
        let jsonString = String(data: data, encoding: .utf8)!
        // ScanResult CodingKeys use snake_case
        #expect(jsonString.contains("\"scan_id\""), "Expected snake_case key 'scan_id'")
        #expect(jsonString.contains("\"macos_version\""), "Expected snake_case key 'macos_version'")
        #expect(jsonString.contains("\"tcc_grants\""), "Expected snake_case key 'tcc_grants'")
        #expect(jsonString.contains("\"bundle_id\""), "Expected snake_case key 'bundle_id'")
        #expect(jsonString.contains("\"hardened_runtime\""), "Expected snake_case key 'hardened_runtime'")
        #expect(jsonString.contains("\"injection_methods\""), "Expected snake_case key 'injection_methods'")
    }

    @Test func securityCriticalFieldsEncodeAsJSONBooleans() throws {
        let exporter = JSONExporter()
        let result = makeSampleScanResult()
        let data = try exporter.encode(result)
        let json = try #require(JSONSerialization.jsonObject(with: data, options: []) as? [String: Any])
        let elevation = try #require(json["elevation"] as? [String: Any])
        assertJSONBool(elevation["is_root"], equals: false, at: "elevation.is_root")
        assertJSONBool(elevation["has_fda"], equals: false, at: "elevation.has_fda")

        let applications = try #require(json["applications"] as? [[String: Any]])
        let app = try #require(applications.first)
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

        let entitlements = try #require(app["entitlements"] as? [[String: Any]])
        let entitlement = try #require(entitlements.first)
        assertJSONBool(entitlement["is_private"], equals: false, at: "applications[0].entitlements[0].is_private")
        assertJSONBool(
            entitlement["is_security_critical"],
            equals: true,
            at: "applications[0].entitlements[0].is_security_critical"
        )
    }

    // MARK: - Round-trip tests

    @Test func roundTripPreservesApplicationData() throws {
        let (original, decoded) = try roundTrippedSampleScanResult()

        #expect(decoded.scanId == original.scanId)
        #expect(decoded.hostname == original.hostname)
        #expect(decoded.macosVersion == original.macosVersion)
        #expect(decoded.collectorVersion == original.collectorVersion)
        #expect(decoded.applications.count == original.applications.count)
        #expect(decoded.tccGrants.count == original.tccGrants.count)
    }

    @Test func roundTripPreservesApplicationProperties() throws {
        let (original, decoded) = try roundTrippedSampleScanResult()

        let origApp = original.applications[0]
        let decApp  = decoded.applications[0]
        #expect(decApp.name == origApp.name)
        #expect(decApp.bundleId == origApp.bundleId)
        #expect(decApp.hardenedRuntime == origApp.hardenedRuntime)
        #expect(decApp.libraryValidation == origApp.libraryValidation)
        #expect(decApp.isElectron == origApp.isElectron)
        #expect(decApp.signed == origApp.signed)
        #expect(decApp.entitlements.count == origApp.entitlements.count)
        #expect(decApp.injectionMethods == origApp.injectionMethods)
    }

    @Test func roundTripPreservesTCCGrant() throws {
        let (original, decoded) = try roundTrippedSampleScanResult()

        let origGrant = original.tccGrants[0]
        let decGrant  = decoded.tccGrants[0]
        #expect(decGrant.service == origGrant.service)
        #expect(decGrant.displayName == origGrant.displayName)
        #expect(decGrant.client == origGrant.client)
        #expect(decGrant.authValue == origGrant.authValue)
        #expect(decGrant.scope == origGrant.scope)
        #expect(decGrant.lastModified == origGrant.lastModified)
    }

    @Test func roundTripPreservesElevationInfo() throws {
        let (original, decoded) = try roundTrippedSampleScanResult()
        #expect(decoded.elevation.isRoot == original.elevation.isRoot)
        #expect(decoded.elevation.hasFda == original.elevation.hasFda)
    }

    @Test func roundTripEmptyScanResult() throws {
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
        #expect(decoded.scanId == empty.scanId)
        #expect(decoded.applications.count == 0)
        #expect(decoded.tccGrants.count == 0)
        #expect(decoded.errors.count == 0)
    }

    // MARK: - Write to file

    @Test func writeProducesReadableFile() throws {
        let exporter = JSONExporter()
        let result = makeSampleScanResult()
        let tmpPath = NSTemporaryDirectory() + "rootstock-test-export.json"
        defer { try? FileManager.default.removeItem(atPath: tmpPath) }
        try exporter.write(result, to: tmpPath)

        let data = try Data(contentsOf: URL(fileURLWithPath: tmpPath))
        let json = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
        #expect(json != nil)
        #expect(json?["scan_id"] as? String == "test-scan-001")
    }

    @Test func writeRefusesExistingFileWithoutForce() throws {
        let exporter = JSONExporter()
        let tmpPath = try existingOutputPath()
        defer { try? FileManager.default.removeItem(atPath: tmpPath) }

        do {
            _ = try exporter.write(makeSampleScanResult(), to: tmpPath)
            Issue.record("Expected error to be thrown")
        } catch {
            #expect(String(describing: error).contains("outputExists"))
        }
    }

    @Test func forceReplacesRegularFileWithOwnerOnlyMode() throws {
        let exporter = JSONExporter()
        let tmpPath = try existingOutputPath()
        defer { try? FileManager.default.removeItem(atPath: tmpPath) }
        chmod(tmpPath, 0o644)

        try exporter.write(makeSampleScanResult(), to: tmpPath, force: true)

        let data = try Data(contentsOf: URL(fileURLWithPath: tmpPath))
        #expect(try JSONSerialization.jsonObject(with: data) as? [String: Any] != nil)

        var info = stat()
        #expect(stat(tmpPath, &info) == 0)
        #expect(info.st_mode & 0o777 == 0o600)
        #expect(!hasExtendedACL(tmpPath))
    }

    @Test func writeCreatesNewFileWithOwnerOnlyMode() throws {
        let exporter = JSONExporter()
        let tmpPath = NSTemporaryDirectory() + "rootstock-test-\(UUID().uuidString).json"
        defer { try? FileManager.default.removeItem(atPath: tmpPath) }

        try exporter.write(makeSampleScanResult(), to: tmpPath)

        var info = stat()
        #expect(stat(tmpPath, &info) == 0)
        #expect(info.st_mode & 0o777 == 0o600)
        #expect(!hasExtendedACL(tmpPath))
    }

    @Test func writeRemovesInheritedExtendedACL() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("rootstock-export-acl-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let chmodProcess = Process()
        chmodProcess.executableURL = URL(fileURLWithPath: "/bin/chmod")
        chmodProcess.arguments = [
            "+a",
            "everyone allow read,readattr,readextattr,readsecurity,file_inherit",
            directory.path,
        ]
        try chmodProcess.run()
        chmodProcess.waitUntilExit()
        try #require(chmodProcess.terminationStatus == 0)

        let output = directory.appendingPathComponent("scan.json")
        try JSONExporter().write(makeSampleScanResult(), to: output.path)

        #expect(!hasExtendedACL(output.path))
    }

    @Test func forcedOverwriteFailurePreservesExistingBytes() throws {
        let path = try existingOutputPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let originalBytes = try Data(contentsOf: URL(fileURLWithPath: path))
        let exporter = JSONExporter(testFailure: .beforePublish)

        do {
            _ = try exporter.write(makeSampleScanResult(), to: path, force: true)
            Issue.record("Expected error to be thrown")
        } catch {
            #expect(String(describing: error).contains("test-injected failure"))
        }

        #expect(try Data(contentsOf: URL(fileURLWithPath: path)) == originalBytes)
        let directory = (path as NSString).deletingLastPathComponent
        let filename = (path as NSString).lastPathComponent
        let temporaryFiles = try FileManager.default.contentsOfDirectory(atPath: directory)
            .filter { $0.hasPrefix(".\(filename).") && $0.hasSuffix(".tmpdir") }
        #expect(temporaryFiles.isEmpty)
    }

    @Test func nonForcePublishDoesNotOverwriteDestinationCreatedDuringExport() throws {
        let path = NSTemporaryDirectory() + "rootstock-test-\(UUID().uuidString).json"
        defer { try? FileManager.default.removeItem(atPath: path) }
        let exporter = JSONExporter(testFailure: .createDestinationBeforePublish)

        do {
            _ = try exporter.write(makeSampleScanResult(), to: path)
            Issue.record("Expected error to be thrown")
        } catch {
            #expect(String(describing: error).contains("outputExists"))
        }
        #expect(try String(contentsOfFile: path) == "racer")
    }

    @Test func postPublishDurabilityFailureKeepsNewCompleteOutput() throws {
        let path = try existingOutputPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let exporter = JSONExporter(testFailure: .afterPublishBeforeDirectorySync)

        do {
            _ = try exporter.write(makeSampleScanResult(), to: path, force: true)
            Issue.record("Expected error to be thrown")
        } catch {
            #expect(String(describing: error).contains("output was published"))
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        #expect(try JSONSerialization.jsonObject(with: data) as? [String: Any] != nil)
    }

    @Test func writeRefusesDirectoryDestinationWithForce() throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("rootstock-export-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        do {
            _ = try JSONExporter().write(makeSampleScanResult(), to: directory.path, force: true)
            Issue.record("Expected error to be thrown")
        } catch {
            #expect(String(describing: error).contains("outputIsNotRegularFile"))
        }
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

    private func hasExtendedACL(_ path: String) -> Bool {
        let descriptor = open(path, O_RDONLY)
        guard descriptor >= 0 else { return true }
        defer { _ = close(descriptor) }
        guard let acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else { return false }
        defer { _ = acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        return acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry) == 0
    }

    @Test func writeRefusesSymlinkEvenWithForce() throws {
        let exporter = JSONExporter()
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("rootstock-export-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let target = dir.appendingPathComponent("target.json")
        let link = dir.appendingPathComponent("link.json")
        try "existing".write(to: target, atomically: false, encoding: .utf8)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)

        do {
            _ = try exporter.write(makeSampleScanResult(), to: link.path, force: true)
            Issue.record("Expected error to be thrown")
        } catch {
            #expect(String(describing: error).contains("outputIsSymlink"))
        }
        #expect(try String(contentsOf: target) == "existing")
    }

    private func assertJSONBool(
        _ value: Any?,
        equals expected: Bool,
        at path: String,
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        guard let value else {
            Issue.record("Missing JSON value at \(path)", sourceLocation: sourceLocation)
            return
        }
        #expect(CFGetTypeID(value as AnyObject) == CFBooleanGetTypeID(), "\(path) must encode as a JSON boolean, not a number", sourceLocation: sourceLocation)
        #expect(value as? Bool == expected, sourceLocation: sourceLocation)
    }
}
