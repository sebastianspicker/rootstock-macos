import XCTest
@testable import RootstockMacFacts

final class RootstockMacFactsTests: XCTestCase {
    func testTCCCatalogContainsFDA() {
        XCTAssertEqual(
            TCCServiceCatalog.displayName(for: TCCServiceCatalog.fullDiskAccessService),
            "Full Disk Access"
        )
        XCTAssertTrue(TCCServiceCatalog.isKnown("kTCCServiceCamera"))
        XCTAssertEqual(
            TCCServiceCatalog.displayName(for: "kTCCServiceUnknownFuture"),
            "kTCCServiceUnknownFuture"
        )
    }

    func testSecurityPathsAreStable() {
        XCTAssertEqual(
            MacSecurityPaths.systemTCCDatabase,
            "/Library/Application Support/com.apple.TCC/TCC.db"
        )
        XCTAssertEqual(MacSecurityPaths.sudoers, "/etc/sudoers")
        XCTAssertTrue(MacSecurityPaths.userTCCDatabaseRelative.contains("TCC.db"))
    }

    func testHostPostureParsers() {
        XCTAssertEqual(HostPostureProbes.parseSIPOutput("System Integrity Protection status: enabled."), true)
        XCTAssertEqual(HostPostureProbes.parseSIPOutput("System Integrity Protection status: disabled."), false)
        XCTAssertNil(HostPostureProbes.parseSIPOutput("garbled"))

        XCTAssertEqual(HostPostureProbes.parseGatekeeperOutput("assessments enabled"), true)
        XCTAssertEqual(HostPostureProbes.parseGatekeeperOutput("assessments disabled"), false)

        XCTAssertEqual(HostPostureProbes.parseFileVaultOutput("FileVault is On."), true)
        XCTAssertEqual(HostPostureProbes.parseFileVaultOutput("FileVault is Off."), false)
        XCTAssertEqual(
            HostPostureProbes.parseFileVaultOutput("Deferred enablement appears to be active."),
            true
        )
        XCTAssertEqual(HostPostureProbes.enabledLabel(true), "true")
        XCTAssertEqual(HostPostureProbes.enabledLabel(nil), "unknown")
    }

    func testHostPostureSnapshotUsesInjectedRunner() {
        let snap = HostPostureProbes.snapshot { path, args in
            switch (path, args) {
            case (HostPostureProbes.csrutilPath, ["status"]):
                return "System Integrity Protection status: enabled."
            case (HostPostureProbes.spctlPath, ["--status"]):
                return "assessments disabled"
            case (HostPostureProbes.fdesetupPath, ["status"]):
                return "FileVault is On."
            default:
                return nil
            }
        }
        XCTAssertEqual(snap.sipEnabled, true)
        XCTAssertEqual(snap.gatekeeperEnabled, false)
        XCTAssertEqual(snap.filevaultEnabled, true)
    }

    func testLaunchdSummarizeFromDict() {
        let dict: [String: Any] = [
            "Label": "com.example.agent",
            "ProgramArguments": ["/usr/bin/true", "--once"],
            "RunAtLoad": true,
            "KeepAlive": false,
            "UserName": "alice",
        ]
        let summary = LaunchdPlistFacts.summarize(path: "/tmp/com.example.agent.plist", dict: dict)
        XCTAssertEqual(summary.label, "com.example.agent")
        XCTAssertEqual(summary.program, "/usr/bin/true")
        XCTAssertEqual(summary.programArguments, ["/usr/bin/true", "--once"])
        XCTAssertEqual(summary.userName, "alice")
        XCTAssertTrue(summary.runAtLoad)
        XCTAssertFalse(summary.keepAlive)
    }

    func testLaunchdListAndSummarizeMissingFile() {
        let summary = LaunchdPlistFacts.summarize(plistPath: "/nonexistent/path.plist")
        XCTAssertEqual(summary.path, "/nonexistent/path.plist")
        XCTAssertNil(summary.label)
        XCTAssertEqual(
            LaunchdPlistFacts.listPlistPaths(in: "/nonexistent/launchd-dir-xyz"),
            []
        )
    }

    func testLaunchdProgramHelpers() {
        let progOnly: [String: Any] = ["Program": "/bin/echo"]
        XCTAssertEqual(LaunchdPlistFacts.program(from: progOnly), "/bin/echo")
        let argsOnly: [String: Any] = ["ProgramArguments": ["/bin/ls", "-la"]]
        XCTAssertEqual(LaunchdPlistFacts.program(from: argsOnly), "/bin/ls")
        XCTAssertTrue(LaunchdPlistFacts.resolveKeepAlive(["PathState": true] as [String: Any]))
        XCTAssertFalse(LaunchdPlistFacts.resolveKeepAlive(false))
    }
}
