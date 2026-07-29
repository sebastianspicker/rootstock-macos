import XCTest
@testable import RootstockBlueFX
@testable import RootstockBlueCore
@testable import RootstockBlueCase
@testable import RootstockBlueDetect

/// Wave-15 multi-plane red↔blue pairs (10 net-new themes beyond Wave-14).
final class Wave15MultiPlanePairTests: XCTestCase {
    var relativeRoot: URL { URL(fileURLWithPath: "Fixtures/artifacts/macos_sample") }
    var absoluteRoot: URL { relativeRoot.standardizedFileURL.resolvingSymlinksInPath() }
    private let wave15IDs = [
        "PHOTOSLIBRARY",
        "VPNCONFIGDUAL",
        "SANDBOXCONTAINER",
        "XPCMACHSERVICE",
        "TMLOCALSNAPSHOT",
        "EMONDLEGACY",
        "SCREENSHARINGARD",
        "KEYCHAINACLPATH",
        "PYTHONRUNTIME",
        "SHELLPLUGINMGR"
    ]
    private let wave15HardenControls = [
        "photos_library_path",
        "vpn_config_dualuse",
        "sandbox_container_depth",
        "xpc_mach_service_depth",
        "tm_local_snapshot_depth",
        "emond_legacy_depth",
        "screen_sharing_ard_depth",
        "keychain_acl_path",
        "python_runtime_dualuse",
        "shell_plugin_manager"
    ]

    func testPluginRuntimeIncludesWave15Parsers() {
        let ids = Set(PluginRuntime().parserIDs())
        for id in wave15IDs { XCTAssertTrue(ids.contains(id), "missing \(id)") }
        for id in ["AUTOMATORWF", "PAMAUTHMODULE", "NOTESMETADATA", "CRONATJOB"] {
            XCTAssertTrue(ids.contains(id), "regression \(id)")
        }
    }

    func testWave15ParsersEmitEventsFromFixtures() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let parsers: [any ArtifactParser] = [
            PhotosLibraryPathParser(),
            VpnConfigDualuseParser(),
            SandboxContainerDepthParser(),
            XpcMachServiceDepthParser(),
            TmLocalSnapshotDepthParser(),
            EmondLegacyDepthParser(),
            ScreenSharingArdDepthParser(),
            KeychainAclPathParser(),
            PythonRuntimeDualuseParser(),
            ShellPluginManagerParser()
        ]
        for parser in parsers {
            let events = try parser.parse(source: .directory(relativeRoot))
            XCTAssertFalse(events.isEmpty, "\(parser.manifest.id)")
            XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == parser.manifest.id })
            for e in events {
                let joined = e.fields.values.joined(separator: " ").lowercased()
                XCTAssertFalse(joined.contains("password=secret"))
                if let exp = e.fields.first(where: { $0.key.hasSuffix("secrets_exported") })?.value {
                    XCTAssertEqual(exp, "false")
                }
            }
        }
    }

    func testRelativeAbsoluteParityWave15() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let parsers: [any ArtifactParser] = [
            PhotosLibraryPathParser(),
            VpnConfigDualuseParser(),
            SandboxContainerDepthParser(),
            XpcMachServiceDepthParser(),
            TmLocalSnapshotDepthParser(),
            EmondLegacyDepthParser(),
            ScreenSharingArdDepthParser(),
            KeychainAclPathParser(),
            PythonRuntimeDualuseParser(),
            ShellPluginManagerParser()
        ]
        for parser in parsers {
            let rel = try parser.parse(source: .directory(relativeRoot))
            let abs = try parser.parse(source: .directory(absoluteRoot))
            XCTAssertEqual(rel.count, abs.count)
            XCTAssertFalse(rel.isEmpty)
        }
    }

    func testHardenAssessSyntheticEmitsTenWave15Controls() {
        let synthetic = HardeningTestFixtures.planeEvents(wave: "wave15", specifications: [
            .init(plugin: "PHOTOSLIBRARY", eventType: "photos.library", fieldPrefix: "photoslib", fileName: "photos_library_path.json", name: "Photos library path plane", riskTag: "photos_surface"),
            .init(plugin: "VPNCONFIGDUAL", eventType: "vpn.config", fieldPrefix: "vpncfg", fileName: "vpn_config_dualuse.json", name: "VPN config dual-use", riskTag: "vpn_surface"),
            .init(plugin: "SANDBOXCONTAINER", eventType: "sandbox.container", fieldPrefix: "sbxctr", fileName: "sandbox_container_depth.json", name: "Sandbox container depth", riskTag: "sandbox_surface"),
            .init(plugin: "XPCMACHSERVICE", eventType: "xpc.mach_service", fieldPrefix: "xpcmach", fileName: "xpc_mach_service_depth.json", name: "XPC Mach service depth", riskTag: "xpc_mach_surface"),
            .init(plugin: "TMLOCALSNAPSHOT", eventType: "tm.local_snapshot", fieldPrefix: "tmsnap", fileName: "tm_local_snapshot_depth.json", name: "TM local snapshot depth", riskTag: "tm_snapshot_surface"),
            .init(plugin: "EMONDLEGACY", eventType: "emond.legacy", fieldPrefix: "emondleg", fileName: "emond_legacy_depth.json", name: "Emond legacy depth", riskTag: "emond_surface"),
            .init(plugin: "SCREENSHARINGARD", eventType: "ard.screen_sharing", fieldPrefix: "ardss", fileName: "screen_sharing_ard_depth.json", name: "Screen Sharing ARD depth", riskTag: "ard_surface"),
            .init(plugin: "KEYCHAINACLPATH", eventType: "keychain.acl_path", fieldPrefix: "kcacl", fileName: "keychain_acl_path.json", name: "Keychain ACL path plane", riskTag: "keychain_acl_surface"),
            .init(plugin: "PYTHONRUNTIME", eventType: "python.runtime", fieldPrefix: "pyrun", fileName: "python_runtime_dualuse.json", name: "Python runtime dual-use", riskTag: "python_surface"),
            .init(plugin: "SHELLPLUGINMGR", eventType: "shell.plugin_manager", fieldPrefix: "shplug", fileName: "shell_plugin_manager.json", name: "Shell plugin manager dual-use", riskTag: "shell_plugin_surface"),
        ])
        let findings = HardeningAssessment.assess(events: synthetic)
        let controls = Set(findings.map(\.control))
        for control in wave15HardenControls {
            XCTAssertTrue(controls.contains(control), "missing \(control); got \(controls.sorted())")
        }
        for finding in findings where wave15HardenControls.contains(finding.control) {
            XCTAssertFalse(finding.remediation.isEmpty)
            XCTAssertFalse((finding.detail + finding.remediation + finding.evidence).lowercased().contains("password=secret"))
        }
    }

    func testWave15DetectionFixturesViaFixtureRunner() throws {
        let rulesDir = URL(fileURLWithPath: "Content/detections/samples")
        let fixturesDir = rulesDir.appendingPathComponent("fixtures")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: rulesDir.path))
        let wave15Rules = [
            "photos_library_path.yaml",
            "vpn_config_dualuse.yaml",
            "sandbox_container_depth.yaml",
            "xpc_mach_service_depth.yaml",
            "tm_local_snapshot_depth.yaml",
            "emond_legacy_depth.yaml",
            "screen_sharing_ard_depth.yaml",
            "keychain_acl_path.yaml",
            "python_runtime_dualuse.yaml",
            "shell_plugin_manager.yaml"
        ]
        var hitIDs: [String] = []
        for name in wave15Rules {
            let rule = try RuleLoader.load(from: rulesDir.appendingPathComponent(name))
            let events = try FixtureRunner.loadEvents(from: fixturesDir.appendingPathComponent(rule.fixture))
            let findings = FixtureRunner.evaluate(rule: rule, events: events)
            XCTAssertFalse(findings.isEmpty, "\(rule.id)")
            XCTAssertEqual(findings.first?.ruleID, rule.id)
            hitIDs.append(rule.id)
        }
        print("WAVE15_DETECTION_RULE_IDS=" + hitIDs.joined(separator: ","))
        print("WAVE15_HARDEN_CONTROLS=" + wave15HardenControls.joined(separator: ","))
    }

    func testMissingMarkersReturnEmptyWave15() throws {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("wave15-empty-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }
        XCTAssertEqual(try PhotosLibraryPathParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try VpnConfigDualuseParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try SandboxContainerDepthParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try XpcMachServiceDepthParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try TmLocalSnapshotDepthParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try EmondLegacyDepthParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try ScreenSharingArdDepthParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try KeychainAclPathParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try PythonRuntimeDualuseParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try ShellPluginManagerParser().parse(source: .directory(tmp)).count, 0)
    }
}
