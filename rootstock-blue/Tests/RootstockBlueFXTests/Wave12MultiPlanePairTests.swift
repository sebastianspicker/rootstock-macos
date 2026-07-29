import XCTest
@testable import RootstockBlueFX
@testable import RootstockBlueCore
@testable import RootstockBlueCase
@testable import RootstockBlueDetect

/// Wave-12 multi-plane red↔blue pairs (6 net-new themes beyond Wave-11).
final class Wave12MultiPlanePairTests: XCTestCase {
    var relativeRoot: URL {
        URL(fileURLWithPath: "Fixtures/artifacts/macos_sample")
    }

    var absoluteRoot: URL {
        relativeRoot.standardizedFileURL.resolvingSymlinksInPath()
    }

    private let wave12IDs = [
        "WEBLOCINETLOC",
        "MAILRULESAUTO",
        "UNIFIEDLOGOBS",
        "DOCKPERSIST",
        "OSASCRIPTSCPT",
        "NETWORKSHAREMOUNT"
    ]

    private let wave12HardenControls = [
        "webloc_inetloc_delivery",
        "mail_rules_automation",
        "unified_log_observation",
        "dock_persistence_surface",
        "osascript_scpt_delivery",
        "network_share_mount"
    ]

    func testPluginRuntimeIncludesWave12Parsers() {
        let ids = Set(PluginRuntime().parserIDs())
        for id in wave12IDs {
            XCTAssertTrue(ids.contains(id), "defaultTier1 missing wave-12 parser \(id)")
        }
        // Regression: Wave-11 still present
        for id in ["URLSCHEMEHANDLER", "LAUNCHDOVERRIDEDEPTH", "BROWSEREXTDUALUSE", "SHORTCUTSAPPINTENTS"] {
            XCTAssertTrue(ids.contains(id), "regression: missing wave-11 \(id)")
        }
    }

    func testWave12ParsersEmitEventsFromFixtures() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let parsers: [any ArtifactParser] = [
            WeblocInetlocParser(),
            MailRulesAutomationParser(),
            UnifiedLogObservationParser(),
            DockPersistenceSurfaceParser(),
            OsascriptScptDeliveryParser(),
            NetworkShareMountParser()
        ]
        for parser in parsers {
            let events = try parser.parse(source: .directory(relativeRoot))
            XCTAssertFalse(events.isEmpty, "\(parser.manifest.id) expected events")
            XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == parser.manifest.id })
            for e in events {
                let joined = e.fields.values.joined(separator: " ").lowercased()
                XCTAssertFalse(joined.contains("password=secret"), "\(parser.manifest.id) no secrets")
                if let exported = e.fields.first(where: { $0.key.hasSuffix("secrets_exported") })?.value {
                    XCTAssertEqual(exported, "false")
                }
            }
        }
    }

    func testRelativeAbsoluteParityWave12() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let parsers: [any ArtifactParser] = [
            WeblocInetlocParser(),
            MailRulesAutomationParser(),
            UnifiedLogObservationParser(),
            DockPersistenceSurfaceParser(),
            OsascriptScptDeliveryParser(),
            NetworkShareMountParser()
        ]
        for parser in parsers {
            let rel = try parser.parse(source: .directory(relativeRoot))
            let abs = try parser.parse(source: .directory(absoluteRoot))
            XCTAssertEqual(rel.count, abs.count, "\(parser.manifest.id) relative/absolute mismatch")
            XCTAssertFalse(rel.isEmpty)
        }
    }

    func testHardenAssessSyntheticEmitsSixWave12Controls() {
        let synthetic = HardeningTestFixtures.planeEvents(wave: "wave12", specifications: [
            .init(plugin: "WEBLOCINETLOC", eventType: "webloc.delivery", fieldPrefix: "webloc", fileName: "webloc_inetloc_delivery.json", name: "Webloc/inetloc delivery", riskTag: "delivery_surface"),
            .init(plugin: "MAILRULESAUTO", eventType: "mail.rules", fieldPrefix: "mail_rules", fileName: "mail_rules_automation.json", name: "Mail rules automation", riskTag: "rules_surface"),
            .init(plugin: "UNIFIEDLOGOBS", eventType: "unified_log.observation", fieldPrefix: "ulog", fileName: "unified_log_observation.json", name: "Unified log observation", riskTag: "observation_surface"),
            .init(plugin: "DOCKPERSIST", eventType: "dock.persistence", fieldPrefix: "dock", fileName: "dock_persistence_surface.json", name: "Dock persistence dual-use", riskTag: "dock_surface"),
            .init(plugin: "OSASCRIPTSCPT", eventType: "osascript.scpt", fieldPrefix: "osa", fileName: "osascript_scpt_delivery.json", name: "OSA/scpt delivery", riskTag: "scpt_surface"),
            .init(plugin: "NETWORKSHAREMOUNT", eventType: "network.share_mount", fieldPrefix: "share", fileName: "network_share_mount.json", name: "Network share mount", riskTag: "share_surface"),
        ])
        let findings = HardeningAssessment.assess(events: synthetic)
        let controls = Set(findings.map(\.control))
        for control in wave12HardenControls {
            XCTAssertTrue(controls.contains(control), "missing harden control \(control); got \(controls.sorted())")
        }
        for finding in findings where wave12HardenControls.contains(finding.control) {
            XCTAssertFalse(finding.remediation.isEmpty, "\(finding.control) remediation")
            XCTAssertFalse((finding.detail + finding.remediation + finding.evidence).lowercased().contains("password=secret"), "\(finding.control) no secrets")
        }
    }

    func testWave12DetectionFixturesViaFixtureRunner() throws {
        let rulesDir = URL(fileURLWithPath: "Content/detections/samples")
        let fixturesDir = rulesDir.appendingPathComponent("fixtures")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: rulesDir.path))

        let wave12Rules = [
            "webloc_inetloc_delivery.yaml",
            "mail_rules_automation.yaml",
            "unified_log_observation.yaml",
            "dock_persistence_surface.yaml",
            "osascript_scpt_delivery.yaml",
            "network_share_mount.yaml"
        ]
        var hitIDs: [String] = []
        for name in wave12Rules {
            let ruleURL = rulesDir.appendingPathComponent(name)
            XCTAssertTrue(FileManager.default.fileExists(atPath: ruleURL.path), "missing rule \(name)")
            let rule = try RuleLoader.load(from: ruleURL)
            let fixtureURL = fixturesDir.appendingPathComponent(rule.fixture)
            XCTAssertTrue(FileManager.default.fileExists(atPath: fixtureURL.path), "missing fixture \(rule.fixture)")
            let events = try FixtureRunner.loadEvents(from: fixtureURL)
            let findings = FixtureRunner.evaluate(rule: rule, events: events)
            XCTAssertFalse(findings.isEmpty, "rule \(rule.id) produced zero findings")
            XCTAssertEqual(findings.first?.ruleID, rule.id)
            hitIDs.append(rule.id)
        }
        print("WAVE12_DETECTION_RULE_IDS=\(hitIDs.joined(separator: ","))")
        print("WAVE12_HARDEN_CONTROLS=\(wave12HardenControls.joined(separator: ","))")
    }

    func testMissingMarkersReturnEmptyWave12() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("wave12-empty-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }
        XCTAssertEqual(try WeblocInetlocParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try MailRulesAutomationParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try UnifiedLogObservationParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try DockPersistenceSurfaceParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try OsascriptScptDeliveryParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try NetworkShareMountParser().parse(source: .directory(tmp)).count, 0)
    }
}
