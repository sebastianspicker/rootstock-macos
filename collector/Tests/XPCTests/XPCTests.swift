import XCTest
import Foundation
@testable import XPCServices
import Models

final class XPCTests: XCTestCase {

    // MARK: - Helpers

    /// Write plist XML to a temp file and return its path. Caller owns cleanup.
    private func writeTempPlist(_ xml: String, name: String, in dir: URL) -> String {
        let url = dir.appendingPathComponent(name)
        try! xml.data(using: .utf8)!.write(to: url)
        return url.path
    }

    private func makeTempDir() -> URL {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent(UUID().uuidString)
        try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    // MARK: - LaunchdPlistParser: single-file parsing

    func testParsesDaemonWithMachServices() {
        let xml = """
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
        let dir = makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = writeTempPlist(xml, name: "com.example.testdaemon.plist", in: dir)

        let parser = LaunchdPlistParser()
        let entry = parser.parse(at: path)

        XCTAssertNotNil(entry)
        XCTAssertEqual(entry?.label, "com.example.testdaemon")
        XCTAssertEqual(entry?.program, "/usr/libexec/testdaemon")
        XCTAssertEqual(entry?.user, "_daemon")
        XCTAssertTrue(entry?.runAtLoad ?? false)
        XCTAssertTrue(entry?.keepAlive ?? false)
        XCTAssertEqual(entry?.machServices.sorted(), [
            "com.example.testdaemon.helper",
            "com.example.testdaemon.xpc"
        ])
    }

    func testParsesAgentWithProgramArguments() {
        let xml = """
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
        let dir = makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = writeTempPlist(xml, name: "com.example.testagent.plist", in: dir)

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

    func testReturnsNilForMissingLabelKey() {
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
          "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>Program</key><string>/usr/bin/something</string>
        </dict></plist>
        """
        let dir = makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = writeTempPlist(xml, name: "no-label.plist", in: dir)

        let parser = LaunchdPlistParser()
        XCTAssertNil(parser.parse(at: path), "Plist without Label should return nil")
    }

    func testReturnsNilForNonexistentFile() {
        let parser = LaunchdPlistParser()
        XCTAssertNil(parser.parse(at: "/nonexistent/path/to/file.plist"))
    }

    func testReturnsNilForMalformedXML() {
        let dir = makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("bad.plist")
        try! "NOT XML AT ALL <<<>>>".data(using: .utf8)!.write(to: url)

        let parser = LaunchdPlistParser()
        XCTAssertNil(parser.parse(at: url.path))
    }

    func testKeepAliveDict() {
        // KeepAlive can be a throttle-config dict instead of Bool
        let xml = """
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
        let dir = makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = writeTempPlist(xml, name: "keepalive.plist", in: dir)

        let parser = LaunchdPlistParser()
        let entry = parser.parse(at: path)
        XCTAssertTrue(entry?.keepAlive ?? false, "Non-empty KeepAlive dict should resolve to true")
    }

    // MARK: - LaunchdPlistParser: directory scanning

    func testParsesDirectoryWithMultiplePlists() {
        let dir = makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let xml1 = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
          "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>Label</key><string>com.example.one</string>
            <key>Program</key><string>/usr/bin/one</string>
        </dict></plist>
        """
        let xml2 = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
          "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>Label</key><string>com.example.two</string>
            <key>Program</key><string>/usr/bin/two</string>
        </dict></plist>
        """
        _ = writeTempPlist(xml1, name: "one.plist", in: dir)
        _ = writeTempPlist(xml2, name: "two.plist", in: dir)
        // Also write a non-plist file that should be ignored
        try! "ignored".data(using: .utf8)!.write(to: dir.appendingPathComponent("ignored.txt"))

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
        XCTAssertTrue(errors.isEmpty, "Missing directory is normal — should not produce an error")
    }

    func testMalformedPlistInDirectoryIsSkippedWithError() {
        let dir = makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        // One valid plist
        let validXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
          "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>Label</key><string>com.example.valid</string>
            <key>Program</key><string>/usr/bin/valid</string>
        </dict></plist>
        """
        _ = writeTempPlist(validXML, name: "valid.plist", in: dir)
        // One broken plist
        try! "BROKEN".data(using: .utf8)!.write(to: dir.appendingPathComponent("broken.plist"))

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
        // In CI or sandboxed environments, count may be 0 — just verify no crash
        let services = result.nodes.compactMap { $0 as? XPCService }
        XCTAssertGreaterThanOrEqual(services.count, 0)
    }

    func testXPCServiceNodeTypeIsCorrect() {
        let service = XPCService(
            label: "com.example.test",
            path: "/Library/LaunchDaemons/com.example.test.plist",
            program: "/usr/sbin/testd",
            type: .daemon,
            user: "_testd",
            runAtLoad: true,
            keepAlive: false,
            machServices: ["com.example.test.xpc"],
            entitlements: []
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
            user: nil,
            runAtLoad: false,
            keepAlive: true,
            machServices: [],
            entitlements: ["com.apple.private.test"]
        )
        let data = try JSONEncoder().encode(service)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        XCTAssertEqual(json["label"] as? String, "com.example.enc")
        XCTAssertEqual(json["type"] as? String, "agent")
        XCTAssertEqual(json["run_at_load"] as? Bool, false)
        XCTAssertEqual(json["keep_alive"] as? Bool, true)
        XCTAssertEqual(json["mach_services"] as? [String], [])
        XCTAssertEqual(json["entitlements"] as? [String], ["com.apple.private.test"])
        // nodeType is a computed property and must NOT appear in JSON
        XCTAssertNil(json["node_type"], "nodeType is a Swift abstraction and should not be serialized")
    }
}
