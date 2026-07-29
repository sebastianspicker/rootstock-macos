import XCTest
@testable import RootstockBlueFX
@testable import RootstockBlueCore
@testable import RootstockBlueCase
@testable import RootstockBlueDetect

/// Wave-14 multi-plane red↔blue pairs (10 net-new themes beyond Wave-13).
final class Wave14MultiPlanePairTests: XCTestCase {
    var relativeRoot: URL { URL(fileURLWithPath: "Fixtures/artifacts/macos_sample") }
    var absoluteRoot: URL { relativeRoot.standardizedFileURL.resolvingSymlinksInPath() }
    private let wave14IDs = [
        "AUTOMATORWF",
        "ICLOUDDRIVEPATH",
        "BTCONTINUITY",
        "FONTVALIDATION",
        "QUICKLOOKCACHE",
        "DNSRESOLVER",
        "LSQUARANTINEDB",
        "PAMAUTHMODULE",
        "CRONATJOB",
        "NOTESMETADATA"
    ]
    private let wave14HardenControls = [
        "automator_workflow",
        "icloud_drive_path",
        "bluetooth_continuity_depth",
        "font_validation_dualuse",
        "quicklook_cache_depth",
        "dns_resolver_dualuse",
        "ls_quarantine_db_depth",
        "pam_auth_module",
        "cron_at_job_depth",
        "notes_metadata_plane"
    ]

    func testPluginRuntimeIncludesWave14Parsers() {
        let ids = Set(PluginRuntime().parserIDs())
        for id in wave14IDs { XCTAssertTrue(ids.contains(id), "missing \(id)") }
        for id in ["CALENDARREMINDERS", "HOMEBREWPKG", "CUPSPRINTDUAL", "SCREENCAPTUREPRIV"] {
            XCTAssertTrue(ids.contains(id), "regression \(id)")
        }
    }

    func testWave14ParsersEmitEventsFromFixtures() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let parsers: [any ArtifactParser] = [
            AutomatorWorkflowParser(),
            IcloudDrivePathParser(),
            BluetoothContinuityDepthParser(),
            FontValidationDualuseParser(),
            QuicklookCacheDepthParser(),
            DnsResolverDualuseParser(),
            LsQuarantineDbDepthParser(),
            PamAuthModuleParser(),
            CronAtJobDepthParser(),
            NotesMetadataPlaneParser()
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

    func testRelativeAbsoluteParityWave14() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let parsers: [any ArtifactParser] = [
            AutomatorWorkflowParser(),
            IcloudDrivePathParser(),
            BluetoothContinuityDepthParser(),
            FontValidationDualuseParser(),
            QuicklookCacheDepthParser(),
            DnsResolverDualuseParser(),
            LsQuarantineDbDepthParser(),
            PamAuthModuleParser(),
            CronAtJobDepthParser(),
            NotesMetadataPlaneParser()
        ]
        for parser in parsers {
            let rel = try parser.parse(source: .directory(relativeRoot))
            let abs = try parser.parse(source: .directory(absoluteRoot))
            XCTAssertEqual(rel.count, abs.count)
            XCTAssertFalse(rel.isEmpty)
        }
    }

    func testHardenAssessSyntheticEmitsTenWave14Controls() {
        let synthetic = HardeningTestFixtures.planeEvents(wave: "wave14", specifications: [
            .init(plugin: "AUTOMATORWF", eventType: "automator.workflow", fieldPrefix: "automator", fileName: "automator_workflow.json", name: "Automator workflow delivery", riskTag: "workflow_surface"),
            .init(plugin: "ICLOUDDRIVEPATH", eventType: "icloud.drive_path", fieldPrefix: "icldrv", fileName: "icloud_drive_path.json", name: "iCloud Drive path plane", riskTag: "icloud_path_surface"),
            .init(plugin: "BTCONTINUITY", eventType: "bluetooth.continuity", fieldPrefix: "btcont", fileName: "bluetooth_continuity_depth.json", name: "Bluetooth Continuity depth", riskTag: "bt_continuity_surface"),
            .init(plugin: "FONTVALIDATION", eventType: "font.validation", fieldPrefix: "fontval", fileName: "font_validation_dualuse.json", name: "Font validation dual-use", riskTag: "font_surface"),
            .init(plugin: "QUICKLOOKCACHE", eventType: "quicklook.cache", fieldPrefix: "qlcache", fileName: "quicklook_cache_depth.json", name: "QuickLook cache depth", riskTag: "quicklook_surface"),
            .init(plugin: "DNSRESOLVER", eventType: "dns.resolver", fieldPrefix: "dnsres", fileName: "dns_resolver_dualuse.json", name: "DNS resolver dual-use", riskTag: "dns_surface"),
            .init(plugin: "LSQUARANTINEDB", eventType: "ls.quarantine_db", fieldPrefix: "lsqdb", fileName: "ls_quarantine_db_depth.json", name: "LS QuarantineEvents depth", riskTag: "quarantine_db_surface"),
            .init(plugin: "PAMAUTHMODULE", eventType: "pam.module", fieldPrefix: "pammod", fileName: "pam_auth_module.json", name: "PAM auth module surface", riskTag: "pam_surface"),
            .init(plugin: "CRONATJOB", eventType: "cron.at_job", fieldPrefix: "cronat", fileName: "cron_at_job_depth.json", name: "Cron/at job depth", riskTag: "cron_at_surface"),
            .init(plugin: "NOTESMETADATA", eventType: "notes.metadata", fieldPrefix: "notesmeta", fileName: "notes_metadata_plane.json", name: "Notes metadata plane", riskTag: "notes_surface"),
        ])
        let findings = HardeningAssessment.assess(events: synthetic)
        let controls = Set(findings.map(\.control))
        for control in wave14HardenControls {
            XCTAssertTrue(controls.contains(control), "missing \(control); got \(controls.sorted())")
        }
        for finding in findings where wave14HardenControls.contains(finding.control) {
            XCTAssertFalse(finding.remediation.isEmpty)
            XCTAssertFalse((finding.detail + finding.remediation + finding.evidence).lowercased().contains("password=secret"))
        }
    }

    func testWave14DetectionFixturesViaFixtureRunner() throws {
        let rulesDir = URL(fileURLWithPath: "Content/detections/samples")
        let fixturesDir = rulesDir.appendingPathComponent("fixtures")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: rulesDir.path))
        let wave14Rules = [
            "automator_workflow.yaml",
            "icloud_drive_path.yaml",
            "bluetooth_continuity_depth.yaml",
            "font_validation_dualuse.yaml",
            "quicklook_cache_depth.yaml",
            "dns_resolver_dualuse.yaml",
            "ls_quarantine_db_depth.yaml",
            "pam_auth_module.yaml",
            "cron_at_job_depth.yaml",
            "notes_metadata_plane.yaml"
        ]
        var hitIDs: [String] = []
        for name in wave14Rules {
            let rule = try RuleLoader.load(from: rulesDir.appendingPathComponent(name))
            let events = try FixtureRunner.loadEvents(from: fixturesDir.appendingPathComponent(rule.fixture))
            let findings = FixtureRunner.evaluate(rule: rule, events: events)
            XCTAssertFalse(findings.isEmpty, "\(rule.id)")
            XCTAssertEqual(findings.first?.ruleID, rule.id)
            hitIDs.append(rule.id)
        }
        print("WAVE14_DETECTION_RULE_IDS=" + hitIDs.joined(separator: ","))
        print("WAVE14_HARDEN_CONTROLS=" + wave14HardenControls.joined(separator: ","))
    }

    func testMissingMarkersReturnEmptyWave14() throws {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("wave14-empty-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }
        XCTAssertEqual(try AutomatorWorkflowParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try IcloudDrivePathParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try BluetoothContinuityDepthParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try FontValidationDualuseParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try QuicklookCacheDepthParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try DnsResolverDualuseParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try LsQuarantineDbDepthParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try PamAuthModuleParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try CronAtJobDepthParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try NotesMetadataPlaneParser().parse(source: .directory(tmp)).count, 0)
    }
}
