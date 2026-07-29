import XCTest
import Foundation
@testable import XPCServices
import Models

final class XPCTests: XCTestCase {

    // MARK: - Helpers

    /// Write plist XML to a temp file and return its path. Caller owns cleanup.
    private func writeTempPlist(_ xml: String, name: String, in dir: URL) throws -> String {
        let url = dir.appendingPathComponent(name)
        try xml.write(to: url, atomically: false, encoding: .utf8)
        return url.path
    }

    private func makeTempDir() throws -> URL {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    // MARK: - LaunchdPlistParser: single-file parsing

    func testParsesDaemonWithMachServices() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = try writeTempPlist(
            Self.daemonWithMachServicesXML,
            name: "com.example.testdaemon.plist",
            in: dir
        )

        let parser = LaunchdPlistParser()
        let entry = parser.parse(at: path)

        assertDaemonWithMachServices(entry)
    }

    private func assertDaemonWithMachServices(
        _ entry: LaunchdPlistParser.ParsedEntry?,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertNotNil(entry)
        XCTAssertEqual(entry?.label, "com.example.testdaemon", file: file, line: line)
        XCTAssertEqual(entry?.program, "/usr/libexec/testdaemon", file: file, line: line)
        XCTAssertEqual(entry?.user, "_daemon", file: file, line: line)
        XCTAssertTrue(entry?.runAtLoad ?? false, file: file, line: line)
        XCTAssertTrue(entry?.keepAlive ?? false, file: file, line: line)
        XCTAssertEqual(entry?.machServices.sorted(), [
            "com.example.testdaemon.helper",
            "com.example.testdaemon.xpc"
        ], file: file, line: line)
    }

    func testParsesAgentWithProgramArguments() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = try writeTempPlist(
            Self.agentWithProgramArgumentsXML,
            name: "com.example.testagent.plist",
            in: dir
        )

        let parser = LaunchdPlistParser()
        let entry = parser.parse(at: path)

        XCTAssertNotNil(entry)
        XCTAssertEqual(entry?.label, "com.example.testagent")
        // ProgramArguments[0] is the binary
        XCTAssertEqual(entry?.program, "/usr/bin/testagent")
        XCTAssertNil(entry?.user)
        XCTAssertFalse(entry?.runAtLoad ?? true)
        XCTAssertFalse(entry?.keepAlive ?? true)
        XCTAssertEqual(entry?.machServices, [])
    }

    func testReturnsNilForMissingLabelKey() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = try writeTempPlist(Self.missingLabelXML, name: "no-label.plist", in: dir)

        let parser = LaunchdPlistParser()
        XCTAssertNil(parser.parse(at: path), "Plist without Label should return nil")
    }

    func testReturnsNilForNonexistentFile() {
        let parser = LaunchdPlistParser()
        XCTAssertNil(parser.parse(at: "/nonexistent/path/to/file.plist"))
    }

    func testReturnsNilForMalformedXML() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("bad.plist")
        let data = try XCTUnwrap("NOT XML AT ALL <<<>>>".data(using: .utf8))
        try data.write(to: url)

        let parser = LaunchdPlistParser()
        XCTAssertNil(parser.parse(at: url.path))
    }

    func testKeepAliveDict() throws {
        // KeepAlive can be a throttle-config dict instead of Bool
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = try writeTempPlist(Self.keepAliveDictXML, name: "keepalive.plist", in: dir)

        let parser = LaunchdPlistParser()
        let entry = parser.parse(at: path)
        XCTAssertTrue(entry?.keepAlive ?? false, "Non-empty KeepAlive dict should resolve to true")
    }

    // MARK: - LaunchdPlistParser: directory scanning

    func testParsesDirectoryWithMultiplePlists() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        _ = try writeTempPlist(Self.directoryEntryOneXML, name: "one.plist", in: dir)
        _ = try writeTempPlist(Self.directoryEntryTwoXML, name: "two.plist", in: dir)
        // Also write a non-plist file that should be ignored
        let ignoredData = try XCTUnwrap("ignored".data(using: .utf8))
        try ignoredData.write(to: dir.appendingPathComponent("ignored.txt"))

        let parser = LaunchdPlistParser()
        let (entries, errors) = parser.parseDirectory(at: dir.path)

        XCTAssertEqual(entries.count, 2)
        XCTAssertTrue(errors.isEmpty)
        let labels = entries.map(\.label).sorted()
        XCTAssertEqual(labels, ["com.example.one", "com.example.two"])
    }

    func testNonexistentDirectoryReturnsEmptyWithoutError() {
        let parser = LaunchdPlistParser()
        let (entries, errors) = parser.parseDirectory(at: "/this/directory/does/not/exist")
        XCTAssertTrue(entries.isEmpty)
        XCTAssertTrue(errors.isEmpty, "Missing directory is normal - should not produce an error")
    }

    func testMalformedPlistInDirectoryIsSkippedWithError() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        // One valid plist
        _ = try writeTempPlist(Self.validDirectoryEntryXML, name: "valid.plist", in: dir)
        // One broken plist
        let brokenData = try XCTUnwrap("BROKEN".data(using: .utf8))
        try brokenData.write(to: dir.appendingPathComponent("broken.plist"))

        let parser = LaunchdPlistParser()
        let (entries, errors) = parser.parseDirectory(at: dir.path)

        XCTAssertEqual(entries.count, 1, "Valid plist should be included")
        XCTAssertEqual(errors.count, 1, "Broken plist should produce one error")
        XCTAssertEqual(entries[0].label, "com.example.valid")
    }

    // MARK: - XPCDataSource integration

    func testXPCDataSourceReturnsDataSourceResult() async {
        let ds = XPCDataSource()
        XCTAssertEqual(ds.name, "XPC Services")
        XCTAssertFalse(ds.requiresElevation)

        let result = await ds.collect()
        // On a real Mac, we expect > 100 services from /System/Library/LaunchDaemons
        // In CI or sandboxed environments, count may be 0 - just verify no crash
        let services = result.nodes.compactMap { $0 as? XPCService }
        XCTAssertGreaterThanOrEqual(services.count, 0)
    }

    func testEntitlementAdmissionFailureIsUnknownWithDiagnostic() {
        let source = XPCDataSource { _, _, _ in .admissionTimedOut }

        let result = source.extractEntitlementKeys(from: "/usr/libexec/example")

        XCTAssertTrue(result.keys.isEmpty)
        XCTAssertTrue(result.error?.message.contains("admission timed out") == true)
    }

    func testUnsignedXPCBinaryHasDefinitivelyEmptyEntitlements() {
        let source = XPCDataSource { _, _, _ in
            .nonZeroExit(Self.shellResult(status: 1, stderr: "code object is not signed"))
        }

        let result = source.extractEntitlementKeys(from: "/usr/libexec/example")

        XCTAssertTrue(result.keys.isEmpty)
        XCTAssertNil(result.error)
    }

    func testSuccessfulXPCEntitlementsAreSorted() {
        let source = XPCDataSource { _, _, _ in
            .success(Self.shellResult(stdout: Self.unorderedEntitlementsXML))
        }

        let result = source.extractEntitlementKeys(from: "/usr/libexec/example")

        XCTAssertEqual(result.keys, ["com.example.alpha", "com.example.zeta"])
        XCTAssertNil(result.error)
    }

    func testXPCServiceNodeTypeIsCorrect() {
        let service = XPCService(
            label: "com.example.test",
            path: "/Library/LaunchDaemons/com.example.test.plist",
            program: "/usr/sbin/testd",
            type: .daemon,
            launch: XPCService.LaunchBehavior(
                user: "_testd",
                runAtLoad: true,
                keepAlive: false
            ),
            exposure: XPCService.Exposure(
                machServices: ["com.example.test.xpc"],
                entitlements: []
            )
        )
        XCTAssertEqual(service.nodeType, "XPCService")
        XCTAssertEqual(service.type, .daemon)
    }

    func testXPCServiceJSONEncoding() throws {
        let service = XPCService(
            label: "com.example.enc",
            path: "/Library/LaunchDaemons/com.example.enc.plist",
            program: nil,
            type: .agent,
            launch: XPCService.LaunchBehavior(
                user: nil,
                runAtLoad: false,
                keepAlive: true
            ),
            exposure: XPCService.Exposure(
                machServices: [],
                entitlements: ["com.apple.private.test"]
            )
        )
        let data = try JSONEncoder().encode(service)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])

        XCTAssertEqual(json["label"] as? String, "com.example.enc")
        XCTAssertEqual(json["type"] as? String, "agent")
        XCTAssertEqual(json["run_at_load"] as? Bool, false)
        XCTAssertEqual(json["keep_alive"] as? Bool, true)
        XCTAssertEqual(json["mach_services"] as? [String], [])
        XCTAssertEqual(json["entitlements"] as? [String], ["com.apple.private.test"])
        // nodeType is a computed property and must NOT appear in JSON
        XCTAssertNil(json["node_type"], "nodeType is a Swift abstraction and should not be serialized")
    }

    private static func shellResult(
        stdout: String = "",
        status: Int32 = 0,
        stderr: String = ""
    ) -> ShellResult {
        ShellResult(
            stdout: stdout,
            stderr: stderr,
            terminationStatus: status,
            timedOut: false
        )
    }

    private static let daemonWithMachServicesXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
          "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>Label</key><string>com.example.testdaemon</string>
            <key>Program</key><string>/usr/libexec/testdaemon</string>
            <key>UserName</key><string>_daemon</string>
            <key>RunAtLoad</key><true/>
            <key>KeepAlive</key><true/>
            <key>MachServices</key><dict>
                <key>com.example.testdaemon.xpc</key><true/>
                <key>com.example.testdaemon.helper</key><true/>
            </dict>
        </dict></plist>
        """

    private static let unorderedEntitlementsXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
          "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
          <key>com.example.zeta</key><true/>
          <key>com.example.alpha</key><true/>
        </dict>
        </plist>
        """

    private static let agentWithProgramArgumentsXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
          "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>Label</key><string>com.example.testagent</string>
            <key>ProgramArguments</key><array>
                <string>/usr/bin/testagent</string>
                <string>--config</string>
                <string>/etc/test.conf</string>
            </array>
            <key>RunAtLoad</key><false/>
        </dict></plist>
        """

    private static let missingLabelXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
          "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>Program</key><string>/usr/bin/something</string>
        </dict></plist>
        """

    private static let keepAliveDictXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
          "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>Label</key><string>com.example.keepalive-dict</string>
            <key>Program</key><string>/usr/bin/x</string>
            <key>KeepAlive</key><dict>
                <key>SuccessfulExit</key><false/>
            </dict>
        </dict></plist>
        """

    private static let directoryEntryOneXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
          "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>Label</key><string>com.example.one</string>
            <key>Program</key><string>/usr/bin/one</string>
        </dict></plist>
        """

    private static let directoryEntryTwoXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
          "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>Label</key><string>com.example.two</string>
            <key>Program</key><string>/usr/bin/two</string>
        </dict></plist>
        """

    private static let validDirectoryEntryXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
          "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>Label</key><string>com.example.valid</string>
            <key>Program</key><string>/usr/bin/valid</string>
        </dict></plist>
        """
}
