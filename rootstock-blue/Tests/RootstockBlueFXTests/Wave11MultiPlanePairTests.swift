import XCTest
@testable import RootstockBlueFX
@testable import RootstockBlueCore
@testable import RootstockBlueCase
@testable import RootstockBlueDetect

/// Wave-11 multi-plane red↔blue pairs:
/// URLSCHEMEHANDLER, LAUNCHDOVERRIDEDEPTH, BROWSEREXTDUALUSE, SHORTCUTSAPPINTENTS
final class Wave11MultiPlanePairTests: XCTestCase {
    var relativeRoot: URL {
        URL(fileURLWithPath: "Fixtures/artifacts/macos_sample")
    }

    var absoluteRoot: URL {
        relativeRoot.standardizedFileURL.resolvingSymlinksInPath()
    }

    private let wave11IDs = [
        "URLSCHEMEHANDLER",
        "LAUNCHDOVERRIDEDEPTH",
        "BROWSEREXTDUALUSE",
        "SHORTCUTSAPPINTENTS",
    ]

    private let wave11HardenControls = [
        "url_scheme_handler",
        "launchd_override_depth",
        "browser_extension_dualuse",
        "shortcuts_app_intents",
    ]

    func testPluginRuntimeIncludesWave11Parsers() {
        let ids = Set(PluginRuntime().parserIDs())
        for id in wave11IDs {
            XCTAssertTrue(ids.contains(id), "defaultTier1 missing wave-11 parser \(id)")
        }
        // Regression: Wave-8 residual pairs still present
        for id in ["PACKAGEKITDESIGN", "ARCHIVEEXTRACTOR", "INFOSTEALERPATH", "TCCESFVISIBILITY"] {
            XCTAssertTrue(ids.contains(id), "regression: missing wave-8 residual \(id)")
        }
    }

    func testURLSchemeHandlerParserEmitsSurface() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try URLSchemeHandlerParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "expected url scheme handler events")
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "URLSCHEMEHANDLER" })
        XCTAssertTrue(events.contains { $0.eventType == "url_scheme.handler" })
        let risk = events.compactMap { $0.fields["url_scheme.risk_tags"] }.joined(separator: ",")
        XCTAssertTrue(risk.contains("handler_surface"), "risk=\(risk)")
    }

    func testLaunchdOverrideDepthParserEmitsSecurityHints() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try LaunchdOverrideDepthParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty)
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "LAUNCHDOVERRIDEDEPTH" })
        XCTAssertTrue(events.contains { $0.eventType == "launchd.override_depth" })
        XCTAssertTrue(events.contains { $0.fields["launchd_depth.security_product_hint"] == "true" })
        let risk = events.compactMap { $0.fields["launchd_depth.risk_tags"] }.joined(separator: ",")
        XCTAssertTrue(risk.contains("security_product_disabled") || risk.contains("override_depth"), "risk=\(risk)")
    }

    func testBrowserExtensionDualUseParserNoSecrets() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try BrowserExtensionDualUseParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty)
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "BROWSEREXTDUALUSE" })
        XCTAssertTrue(events.contains { $0.eventType == "browser.extension_dualuse" })
        for e in events {
            XCTAssertEqual(e.fields["ext_dualuse.secrets_exported"], "false")
            XCTAssertNil(e.fields["password"])
            XCTAssertNil(e.fields["cookie"])
            let joined = e.fields.values.joined(separator: " ").lowercased()
            XCTAssertFalse(joined.contains("supersecret"), "must not dump secrets")
        }
        let risk = events.compactMap { $0.fields["ext_dualuse.risk_tags"] }.joined(separator: ",")
        XCTAssertTrue(risk.contains("dual_use_surface"), "risk=\(risk)")
    }

    func testShortcutsAppIntentsParserEmitsAutomation() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try ShortcutsAppIntentsParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty)
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "SHORTCUTSAPPINTENTS" })
        XCTAssertTrue(events.contains { $0.eventType == "shortcuts.automation" })
        let risk = events.compactMap { $0.fields["shortcuts.risk_tags"] }.joined(separator: ",")
        XCTAssertTrue(risk.contains("automation_surface"), "risk=\(risk)")
    }

    func testRelativeAbsoluteParityWave11() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let parsers: [any ArtifactParser] = [
            URLSchemeHandlerParser(),
            LaunchdOverrideDepthParser(),
            BrowserExtensionDualUseParser(),
            ShortcutsAppIntentsParser(),
        ]
        for parser in parsers {
            let rel = try parser.parse(source: .directory(relativeRoot))
            let abs = try parser.parse(source: .directory(absoluteRoot))
            XCTAssertEqual(
                rel.count,
                abs.count,
                "\(parser.manifest.id) relative/absolute count mismatch \(rel.count) vs \(abs.count)"
            )
            XCTAssertFalse(rel.isEmpty, "\(parser.manifest.id) produced zero events")
        }
    }

    func testHardenAssessSyntheticEmitsFourWave11Controls() {
        let synthetic = [
            HardeningTestFixtures.event("URLSCHEMEHANDLER", "url_scheme.handler", [
                "url_scheme.handler_path": "/Users/alice/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist", "url_scheme.scheme": "rootstock-lab", "url_scheme.risk_tags": "handler_surface,custom_scheme",
            ]),
            HardeningTestFixtures.event("LAUNCHDOVERRIDEDEPTH", "launchd.override_depth", [
                "launchd_depth.label": "com.google.santa", "launchd_depth.override_path": "/var/db/com.apple.xpc.launchd/disabled.plist", "launchd_depth.security_product_hint": "true", "launchd_depth.risk_tags": "override_depth,security_product_disabled",
            ]),
            HardeningTestFixtures.event("BROWSEREXTDUALUSE", "browser.extension_dualuse", [
                "ext_dualuse.browser": "chrome", "ext_dualuse.path": "/Users/alice/Library/Application Support/Google/Chrome/Default/Extensions/abc", "ext_dualuse.extension_id": "abc", "ext_dualuse.risk_tags": "dual_use_surface,broad_permissions", "ext_dualuse.secrets_exported": "false",
            ]),
            HardeningTestFixtures.event("SHORTCUTSAPPINTENTS", "shortcuts.automation", [
                "shortcuts.path": "/Users/alice/Library/Shortcuts", "shortcuts.name": "Lab Automation", "shortcuts.risk_tags": "automation_surface,scripting_action",
            ]),
        ]
        let findings = HardeningAssessment.assess(events: synthetic)
        let controls = Set(findings.map(\.control))
        for control in wave11HardenControls {
            XCTAssertTrue(controls.contains(control), "missing harden control \(control); got \(controls.sorted())")
        }
        for finding in findings where wave11HardenControls.contains(finding.control) {
            XCTAssertFalse(finding.remediation.isEmpty, "\(finding.control) remediation")
            XCTAssertFalse(finding.title.isEmpty)
            let blob = (finding.detail + finding.remediation + finding.evidence).lowercased()
            XCTAssertFalse(blob.contains("password=secret"), "\(finding.control) no secrets")
            XCTAssertFalse(blob.contains("value_exported=true"), "\(finding.control) no secret export")
        }
    }

    func testWave11DetectionFixturesViaFixtureRunner() throws {
        let rulesDir = URL(fileURLWithPath: "Content/detections/samples")
        let fixturesDir = rulesDir.appendingPathComponent("fixtures")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: rulesDir.path))

        let wave11Rules = [
            "url_scheme_handler.yaml",
            "launchd_override_depth.yaml",
            "browser_extension_dualuse.yaml",
            "shortcuts_app_intents.yaml",
        ]
        var hitIDs: [String] = []
        for name in wave11Rules {
            let ruleURL = rulesDir.appendingPathComponent(name)
            XCTAssertTrue(FileManager.default.fileExists(atPath: ruleURL.path), "missing rule \(name)")
            let rule = try RuleLoader.load(from: ruleURL)
            let fixtureURL = fixturesDir.appendingPathComponent(rule.fixture)
            XCTAssertTrue(
                FileManager.default.fileExists(atPath: fixtureURL.path),
                "missing fixture \(rule.fixture) for \(rule.id)"
            )
            let events = try FixtureRunner.loadEvents(from: fixtureURL)
            let findings = FixtureRunner.evaluate(rule: rule, events: events)
            XCTAssertFalse(findings.isEmpty, "rule \(rule.id) produced zero findings on its fixture")
            XCTAssertEqual(findings.first?.ruleID, rule.id)
            hitIDs.append(rule.id)
        }
        print("WAVE11_DETECTION_RULE_IDS=\(hitIDs.joined(separator: ","))")
        print("WAVE11_HARDEN_CONTROLS=\(wave11HardenControls.joined(separator: ","))")
    }

    func testMissingMarkersReturnEmptyWave11() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("wave11-empty-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }
        XCTAssertEqual(try URLSchemeHandlerParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try LaunchdOverrideDepthParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try BrowserExtensionDualUseParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try ShortcutsAppIntentsParser().parse(source: .directory(tmp)).count, 0)
    }
}
