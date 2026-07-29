import XCTest
@testable import RootstockBlueCollect
@testable import RootstockBlueCase
@testable import RootstockBlueCore

final class CollectTests: XCTestCase {
    func testCollectWritesArtifactsAndEvents() throws {
        let fixture = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("Fixtures/artifacts/macos_sample")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: fixture.path))

        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("cf-collect-\(UUID().uuidString).rsbcase")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let pkg = try CasePackage.create(at: tmp, name: "collect-test")

        let pack = CollectionPack(
            name: "triage-lite",
            description: "test",
            requiresFDA: true,
            requiresES: false,
            artifacts: ["tcc", "quarantine", "autostart", "users"]
        )
        let runner = CollectRunner(skipStrictPreflight: true)
        let result = try runner.run(pack: pack, sourceRoot: fixture, into: pkg)
        XCTAssertGreaterThan(result.filesCopied, 0)
        XCTAssertGreaterThan(result.eventsWritten, 0)
        XCTAssertTrue(result.preflight.passed)

        let events = try pkg.loadAllEvents()
        XCTAssertTrue(events.contains { $0.eventType == "collect.summary" })
        XCTAssertTrue(events.contains { $0.eventType == "collect.artifact" })
    }

    func testPreflightLiveRequiresFDA() {
        let pack = CollectionPack(name: "x", description: "", requiresFDA: true, requiresES: false, artifacts: [])
        let live = Preflight.check(for: pack, offlineFixtureMode: false)
        XCTAssertFalse(live.passed)
        let offline = Preflight.check(for: pack, offlineFixtureMode: true)
        XCTAssertTrue(offline.passed)
    }

    private func assertArtifactPath(
        _ artifact: String,
        exactPaths: [String] = [],
        containing fragments: [String] = []
    ) {
        let paths = CollectRunner.artifactPaths(for: artifact)
        XCTAssertTrue(paths.contains { path in
            exactPaths.contains(path) || fragments.contains { path.contains($0) }
        })
    }

    func testArtifactPathsExpandedMappings() {
        assertArtifactPath("btm", containing: ["backgroundtaskmanagement"])
        assertArtifactPath("wifi", containing: ["airport.preferences", "wifi"])
        XCTAssertEqual(CollectRunner.artifactPaths(for: "security_posture"), ["Library/Preferences/security_posture.json"])
        XCTAssertEqual(CollectRunner.artifactPaths(for: "alf"), ["Library/Preferences/com.apple.alf.plist"])
        assertArtifactPath("ssh", exactPaths: ["Users"])
        assertArtifactPath("configprofiles", containing: ["ConfigurationProfiles", "Managed Preferences"])
        XCTAssertFalse(CollectRunner.artifactPaths(for: "btm").contains("Library/LaunchAgents"))

        assertArtifactPath("cron", containing: ["crontab", "at/tabs"])
        assertArtifactPath("loginitems", exactPaths: ["Users"], containing: ["sharedfilelist"])
        assertArtifactPath("systemextensions", containing: ["SystemExtensions"])
        assertArtifactPath("utmpx", containing: ["utmpx"])
        assertArtifactPath("biome", containing: ["Biome"])
        assertArtifactPath("gatekeeper", containing: ["Gatekeeper", "gk.json"])
        assertArtifactPath("netlocation", containing: ["network_locations", "SystemConfiguration"])
        assertArtifactPath("browser_extensions", exactPaths: ["Users"], containing: ["Chrome"])
        assertArtifactPath("shell_profiles", exactPaths: ["Users"], containing: ["profile"])
        assertArtifactPath("emond", containing: ["emond"])
        assertArtifactPath("sudoers", containing: ["sudoers"])
        assertArtifactPath("launchd_overrides", containing: ["xpc.launchd", "launchd_disabled"])
        assertArtifactPath("privhelpers", containing: ["PrivilegedHelperTools"])
        assertArtifactPath("folder_actions", exactPaths: ["Users"], containing: ["Scripts"])
        assertArtifactPath("login_hooks", containing: ["loginwindow", "login_hooks"])
        assertArtifactPath("software_update", containing: ["SoftwareUpdate"])
        assertArtifactPath("file_sharing", containing: ["smb", "AppleFileServer"])
    }

    func testNetworkAndAccessSurfacePacksLoad() throws {
        let cwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        for name in ["network-context", "access-surface", "persistence", "forensic-triage"] {
            let url = cwd.appendingPathComponent("Content/collections/\(name).yaml")
            try XCTSkipIf(!FileManager.default.fileExists(atPath: url.path))
            let pack = try CollectionPackLoader.load(from: url)
            XCTAssertEqual(pack.name, name)
            XCTAssertFalse(pack.artifacts.isEmpty)
        }
    }

    func testPostIncidentIRPackLoadsAndCollectsPosture() throws {
        let content = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("Content/collections/post-incident-ir.yaml")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: content.path))
        let pack = try CollectionPackLoader.load(from: content)
        XCTAssertEqual(pack.name, "post-incident-ir")
        XCTAssertTrue(pack.artifacts.contains("security_posture"))
        XCTAssertTrue(pack.artifacts.contains("btm"))
        XCTAssertTrue(pack.artifacts.contains("alf"))

        let fixture = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("Fixtures/artifacts/macos_sample")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: fixture.path))
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("cf-post-ir-\(UUID().uuidString).rsbcase")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let pkg = try CasePackage.create(at: tmp, name: "post-ir")
        let result = try CollectRunner(skipStrictPreflight: true).run(
            pack: pack,
            sourceRoot: fixture,
            into: pkg
        )
        // security_posture.json and alf.plist exist in fixture
        XCTAssertGreaterThan(result.filesCopied, 0)
        let events = try pkg.loadAllEvents()
        XCTAssertTrue(events.contains {
            $0.fields["collect.artifact"] == "security_posture"
                || ($0.fields["collect.relative"] ?? "").contains("security_posture")
        })
    }
}
