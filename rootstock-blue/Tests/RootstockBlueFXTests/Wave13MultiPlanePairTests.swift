import XCTest
@testable import RootstockBlueFX
@testable import RootstockBlueCore
@testable import RootstockBlueCase
@testable import RootstockBlueDetect

/// Wave-13 multi-plane red↔blue pairs (5 net-new themes beyond Wave-12).
final class Wave13MultiPlanePairTests: XCTestCase {
    var relativeRoot: URL { URL(fileURLWithPath: "Fixtures/artifacts/macos_sample") }
    var absoluteRoot: URL { relativeRoot.standardizedFileURL.resolvingSymlinksInPath() }

    private let wave13IDs = [
        "CALENDARREMINDERS",
        "GKASSESSMENTHIST",
        "HOMEBREWPKG",
        "CUPSPRINTDUAL",
        "SCREENCAPTUREPRIV"
    ]
    private let wave13HardenControls = [
        "calendar_reminders_automation",
        "gatekeeper_assessment_history",
        "homebrew_package_dualuse",
        "cups_print_dualuse",
        "screencapture_privacy_dualuse"
    ]

    func testPluginRuntimeIncludesWave13Parsers() {
        let ids = Set(PluginRuntime().parserIDs())
        for id in wave13IDs {
            XCTAssertTrue(ids.contains(id), "missing wave-13 parser \(id)")
        }
        for id in ["WEBLOCINETLOC", "MAILRULESAUTO", "UNIFIEDLOGOBS", "DOCKPERSIST", "OSASCRIPTSCPT", "NETWORKSHAREMOUNT"] {
            XCTAssertTrue(ids.contains(id), "regression missing wave-12 \(id)")
        }
    }

    func testWave13ParsersEmitEventsFromFixtures() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let parsers: [any ArtifactParser] = [
            CalendarRemindersAutomationParser(),
            GatekeeperAssessmentHistoryParser(),
            HomebrewPackageDualUseParser(),
            CupsPrintDualUseParser(),
            ScreenCapturePrivacyDualUseParser()
        ]
        for parser in parsers {
            let events = try parser.parse(source: .directory(relativeRoot))
            XCTAssertFalse(events.isEmpty, "\(parser.manifest.id) expected events")
            XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == parser.manifest.id })
            for e in events {
                let joined = e.fields.values.joined(separator: " ").lowercased()
                XCTAssertFalse(joined.contains("password=secret"))
                if let exported = e.fields.first(where: { $0.key.hasSuffix("secrets_exported") })?.value {
                    XCTAssertEqual(exported, "false")
                }
            }
        }
    }

    func testRelativeAbsoluteParityWave13() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let parsers: [any ArtifactParser] = [
            CalendarRemindersAutomationParser(),
            GatekeeperAssessmentHistoryParser(),
            HomebrewPackageDualUseParser(),
            CupsPrintDualUseParser(),
            ScreenCapturePrivacyDualUseParser()
        ]
        for parser in parsers {
            let rel = try parser.parse(source: .directory(relativeRoot))
            let abs = try parser.parse(source: .directory(absoluteRoot))
            XCTAssertEqual(rel.count, abs.count)
            XCTAssertFalse(rel.isEmpty)
        }
    }

    func testHardenAssessSyntheticEmitsFiveWave13Controls() {
        let synthetic = HardeningTestFixtures.planeEvents(wave: "wave13", specifications: [
            .init(plugin: "CALENDARREMINDERS", eventType: "calendar.reminders", fieldPrefix: "calrem", fileName: "calendar_reminders_automation.json", name: "Calendar/Reminders automation", riskTag: "automation_surface"),
            .init(plugin: "GKASSESSMENTHIST", eventType: "gatekeeper.assessment", fieldPrefix: "gkh", fileName: "gatekeeper_assessment_history.json", name: "Gatekeeper assessment history", riskTag: "assessment_surface"),
            .init(plugin: "HOMEBREWPKG", eventType: "homebrew.package", fieldPrefix: "brew", fileName: "homebrew_package_dualuse.json", name: "Homebrew package dual-use", riskTag: "package_surface"),
            .init(plugin: "CUPSPRINTDUAL", eventType: "cups.print", fieldPrefix: "cups", fileName: "cups_print_dualuse.json", name: "CUPS printer dual-use", riskTag: "print_surface"),
            .init(plugin: "SCREENCAPTUREPRIV", eventType: "screencapture.privacy", fieldPrefix: "scpriv", fileName: "screencapture_privacy_dualuse.json", name: "ScreenCapture privacy dual-use", riskTag: "capture_surface"),
        ])
        let findings = HardeningAssessment.assess(events: synthetic)
        let controls = Set(findings.map(\.control))
        for control in wave13HardenControls {
            XCTAssertTrue(controls.contains(control), "missing harden \(control); got \(controls.sorted())")
        }
        for finding in findings where wave13HardenControls.contains(finding.control) {
            XCTAssertFalse(finding.remediation.isEmpty)
            XCTAssertFalse((finding.detail + finding.remediation + finding.evidence).lowercased().contains("password=secret"))
        }
    }

    func testWave13DetectionFixturesViaFixtureRunner() throws {
        let rulesDir = URL(fileURLWithPath: "Content/detections/samples")
        let fixturesDir = rulesDir.appendingPathComponent("fixtures")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: rulesDir.path))
        let wave13Rules = [
            "calendar_reminders_automation.yaml",
            "gatekeeper_assessment_history.yaml",
            "homebrew_package_dualuse.yaml",
            "cups_print_dualuse.yaml",
            "screencapture_privacy_dualuse.yaml"
        ]
        var hitIDs: [String] = []
        for name in wave13Rules {
            let ruleURL = rulesDir.appendingPathComponent(name)
            XCTAssertTrue(FileManager.default.fileExists(atPath: ruleURL.path))
            let rule = try RuleLoader.load(from: ruleURL)
            let fixtureURL = fixturesDir.appendingPathComponent(rule.fixture)
            XCTAssertTrue(FileManager.default.fileExists(atPath: fixtureURL.path))
            let events = try FixtureRunner.loadEvents(from: fixtureURL)
            let findings = FixtureRunner.evaluate(rule: rule, events: events)
            XCTAssertFalse(findings.isEmpty, "rule \(rule.id) zero findings")
            XCTAssertEqual(findings.first?.ruleID, rule.id)
            hitIDs.append(rule.id)
        }
        print("WAVE13_DETECTION_RULE_IDS=" + hitIDs.joined(separator: ","))
        print("WAVE13_HARDEN_CONTROLS=" + wave13HardenControls.joined(separator: ","))
    }

    func testMissingMarkersReturnEmptyWave13() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("wave13-empty-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }
        XCTAssertEqual(try CalendarRemindersAutomationParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try GatekeeperAssessmentHistoryParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try HomebrewPackageDualUseParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try CupsPrintDualUseParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try ScreenCapturePrivacyDualUseParser().parse(source: .directory(tmp)).count, 0)
    }
}
