import XCTest
import Foundation
@testable import ProcessSnapshot
import Models

final class ProcessSnapshotTests: XCTestCase {

    func testRunningProcessNodeType() {
        let proc = RunningProcess(pid: 1234, user: "root", command: "/usr/sbin/httpd", bundleId: nil)
        XCTAssertEqual(proc.nodeType, "RunningProcess")
    }

    func testRunningProcessJSONEncoding() throws {
        let proc = RunningProcess(pid: 42, user: "admin", command: "/Applications/Safari.app/Contents/MacOS/Safari", bundleId: "com.apple.Safari")
        let data = try JSONEncoder().encode(proc)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(json["pid"] as? Int, 42)
        XCTAssertEqual(json["bundle_id"] as? String, "com.apple.Safari")
    }

    func testParsePsOutputBasic() {
        let output = """
          PID USER             COMM
            1 root             /sbin/launchd
          123 admin            /Applications/Safari.app/Contents/MacOS/Safari
          456 admin            /usr/sbin/httpd
        """
        let apps = [
            Application(
                identity: Application.Identity(
                    name: "Safari",
                    bundleId: "com.apple.Safari",
                    path: "/Applications/Safari.app",
                    version: nil
                ),
                flags: Application.Flags(isElectron: false, isSystem: true),
                signing: Application.Signing(
                    hardenedRuntime: true,
                    libraryValidation: true,
                    signed: true
                )
            ),
        ]
        let processes = ProcessSnapshotDataSource.parsePsOutput(output, knownApps: apps)
        XCTAssertEqual(processes.count, 3)
        XCTAssertEqual(processes[0].bundleId, nil)
        XCTAssertEqual(processes[0].pid, 1)
        XCTAssertEqual(processes[1].bundleId, "com.apple.Safari")
        XCTAssertEqual(processes[1].pid, 123)
        XCTAssertEqual(processes[1].user, "admin")
        XCTAssertEqual(processes[2].bundleId, nil)
        XCTAssertEqual(processes[2].command, "/usr/sbin/httpd")
    }

    func testParsePsOutputEmpty() {
        let processes = ProcessSnapshotDataSource.parsePsOutput("", knownApps: [])
        XCTAssertTrue(processes.isEmpty)
    }

    func testProcessSnapshotDataSourceMetadata() {
        let ds = ProcessSnapshotDataSource()
        XCTAssertEqual(ds.name, "Process Snapshot")
        XCTAssertFalse(ds.requiresElevation)
    }

    func testParsePsOutputResolvesSymlinkedAppPaths() throws {
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("test-ps-symlink-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let realApp = tempDir.appendingPathComponent("Real.app")
        let symlinkApp = tempDir.appendingPathComponent("Linked.app")
        try FileManager.default.createDirectory(at: realApp, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: symlinkApp, withDestinationURL: realApp)

        let output = "321 admin \(realApp.path)/Contents/MacOS/Real"
        let apps = [
            Application(
                identity: Application.Identity(
                    name: "Linked",
                    bundleId: "com.example.linked",
                    path: symlinkApp.path,
                    version: nil
                ),
                flags: Application.Flags(isElectron: false, isSystem: false),
                signing: Application.Signing(
                    hardenedRuntime: true,
                    libraryValidation: true,
                    signed: true
                )
            ),
        ]

        let processes = ProcessSnapshotDataSource.parsePsOutput(output, knownApps: apps)
        XCTAssertEqual(processes.count, 1)
        XCTAssertEqual(processes.first?.bundleId, "com.example.linked")
    }
}
