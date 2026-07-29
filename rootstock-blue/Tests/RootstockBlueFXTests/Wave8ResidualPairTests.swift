import XCTest
@testable import RootstockBlueFX
@testable import RootstockBlueCore
@testable import RootstockBlueCase
@testable import RootstockBlueDetect

/// Wave-8 residual red↔blue pairs:
/// PACKAGEKITDESIGN, ARCHIVEEXTRACTOR, INFOSTEALERPATH, TCCESFVISIBILITY
/// + harden controls with remediation + fixture-backed detections.
final class Wave8ResidualPairTests: XCTestCase {
    var relativeRoot: URL {
        URL(fileURLWithPath: "Fixtures/artifacts/macos_sample")
    }

    var absoluteRoot: URL {
        relativeRoot.standardizedFileURL.resolvingSymlinksInPath()
    }

    private let wave8IDs = [
        "PACKAGEKITDESIGN",
        "ARCHIVEEXTRACTOR",
        "INFOSTEALERPATH",
        "TCCESFVISIBILITY",
    ]

    private let wave8HardenControls = [
        "packagekit_installer_design",
        "archive_quarantine_extractor",
        "infostealer_path_plane",
        "tcc_esf_visibility_depth",
    ]

    // MARK: - Runtime registration

    func testPluginRuntimeIncludesWave8Parsers() {
        let ids = Set(PluginRuntime().parserIDs())
        for id in wave8IDs {
            XCTAssertTrue(ids.contains(id), "defaultTier1 missing wave-8 parser \(id)")
        }
        // Regression: Wave-7 still present
        for id in ["COOKIES", "BOOKMARKS", "CLOUDSYNC", "MSRDC"] {
            XCTAssertTrue(ids.contains(id), "regression: missing wave-7 family \(id)")
        }
    }

    // MARK: - Family parsers (fixture-backed when tree present)

    func testPackageKitDesignParserEmitsDesignSurface() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try PackageKitDesignParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "expected packagekit design events")
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "PACKAGEKITDESIGN" })
        XCTAssertTrue(events.contains { $0.eventType == "packagekit.design" })
        let risk = events.compactMap { $0.fields["packagekit.risk_tags"] }.joined(separator: ",")
        XCTAssertTrue(risk.contains("design_surface"), "risk=\(risk)")
        XCTAssertTrue(events.contains { $0.fields["packagekit.service_present"] == "true" })
        for e in events {
            let joined = (e.fields.values + [e.fields["packagekit.notes"] ?? ""]).joined(separator: " ").lowercased()
            XCTAssertFalse(joined.contains("build malicious pkg"), "must not claim to build pkgs")
            XCTAssertFalse(joined.contains("builds pkgs") && joined.contains("will build"))
        }
    }

    func testArchiveExtractorParserEmitsThirdParty() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try ArchiveExtractorParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty)
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "ARCHIVEEXTRACTOR" })
        XCTAssertTrue(events.contains { $0.eventType == "archive.extractor" })
        XCTAssertTrue(events.contains { $0.fields["archive.third_party"] == "true" })
        let risk = events.compactMap { $0.fields["archive.risk_tags"] }.joined(separator: ",")
        XCTAssertTrue(
            risk.contains("third_party_extractor") || risk.contains("quarantine_non_inherit"),
            "risk=\(risk)"
        )
    }

    func testInfoStealerPathParserNoSecrets() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try InfoStealerPathParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty)
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "INFOSTEALERPATH" })
        XCTAssertTrue(events.contains { $0.eventType == "stealer.path" })
        let families = Set(events.compactMap { $0.fields["stealer.path_family"] })
        XCTAssertTrue(families.count >= 2, "families=\(families)")
        let risk = events.compactMap { $0.fields["stealer.risk_tags"] }.joined(separator: ",")
        XCTAssertTrue(risk.contains("multi_app_collection") || risk.contains("fda_adjacent"), "risk=\(risk)")
        for e in events {
            XCTAssertEqual(e.fields["stealer.secrets_exported"], "false")
            XCTAssertNil(e.fields["password"])
            XCTAssertNil(e.fields["cookie"])
            XCTAssertNil(e.fields["cookie.value"])
            XCTAssertNil(e.fields["secret"])
            let joined = e.fields.values.joined(separator: " ").lowercased()
            XCTAssertFalse(joined.contains("supersecret"), "must not dump secrets")
            XCTAssertFalse(joined.contains("password=secret"))
        }
    }

    func testTCCESFVisibilityParserEmitsDepth() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try TCCESFVisibilityParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty)
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "TCCESFVISIBILITY" })
        XCTAssertTrue(events.contains { $0.eventType == "tcc_esf.visibility" })
        let depths = events.compactMap { $0.fields["visibility.depth"] }
        XCTAssertTrue(depths.contains("thin") || depths.contains("partial") || depths.contains("strong"))
        let risk = events.compactMap { $0.fields["visibility.risk_tags"] }.joined(separator: ",")
        XCTAssertTrue(
            risk.contains("thin_visibility") || risk.contains("partial_visibility")
                || risk.contains("sensor_gap"),
            "risk=\(risk)"
        )
    }

    func testRelativeAbsoluteParityWave8() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let parsers: [any ArtifactParser] = [
            PackageKitDesignParser(),
            ArchiveExtractorParser(),
            InfoStealerPathParser(),
            TCCESFVisibilityParser(),
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

    // MARK: - Hardening (gating pure path - MUST NOT skip)

    private func assertWave8ControlFindings(_ findings: [HardeningAssessment.Finding]) {
        for control in wave8HardenControls {
            let matching = findings.contains { finding in
                finding.control == control && ["fail", "warn"].contains(finding.status)
            }
            XCTAssertTrue(matching, "expected fail/warn for \(control); have \(findings.map { "\($0.control):\($0.status)" })")
            XCTAssertFalse(findings.first { $0.control == control }!.remediation.isEmpty, "empty remediation for \(control)")
        }
    }

    private func assertWave8NonGoals(_ findings: [HardeningAssessment.Finding]) {
        if let packageKit = findings.first(where: { $0.control == "packagekit_installer_design" }) {
            let blob = (packageKit.detail + " " + packageKit.remediation + " " + packageKit.title).lowercased()
            XCTAssertFalse(blob.contains("build malicious pkg"))
            XCTAssertFalse(blob.contains("build a malicious package"))
            XCTAssertFalse(blob.contains("weaponize installd"))
        }
        if let stealer = findings.first(where: { $0.control == "infostealer_path_plane" }) {
            let blob = (stealer.detail + " " + stealer.remediation + " " + stealer.evidence).lowercased()
            XCTAssertFalse(blob.contains("password=secret"))
            XCTAssertFalse(blob.contains("cookie_value="))
            XCTAssertFalse(blob.contains("-----begin"))
            let safeLanguage = ["not export", "do not dump", "secrets not"].contains { blob.contains($0) }
                || stealer.detail.lowercased().contains("not exported")
                || stealer.remediation.lowercased().contains("do not dump")
            XCTAssertTrue(safeLanguage)
        }
    }

    func testHardenAssessSyntheticEmitsFourPairControls() {
        let synthetic = [
            HardeningTestFixtures.event("PACKAGEKITDESIGN", "packagekit.design", ["packagekit.service_present": "true", "packagekit.receipt_paths": "/Library/Receipts,/var/db/receipts", "packagekit.plugin_paths": "/Library/Installer Plugins", "packagekit.risk_tags": "design_surface,installer_service", "packagekit.notes": "PackageKit design surface path presence only"]),
            HardeningTestFixtures.event("ARCHIVEEXTRACTOR", "archive.extractor", ["archive.extractor_name": "Keka", "archive.extractor_path": "/Applications/Keka.app", "archive.third_party": "true", "archive.drop_hint": "/Users/alice/Downloads", "archive.risk_tags": "third_party_extractor,quarantine_non_inherit"]),
            HardeningTestFixtures.event("INFOSTEALERPATH", "stealer.path", ["stealer.path_family": "browser", "stealer.path": "/Users/alice/Library/Application Support/Google/Chrome", "stealer.fda_adjacent": "true", "stealer.risk_tags": "multi_app_collection,fda_adjacent", "stealer.secrets_exported": "false"]),
            HardeningTestFixtures.event("INFOSTEALERPATH", "stealer.path", ["stealer.path_family": "vault", "stealer.path": "/Users/alice/Library/Application Support/1Password", "stealer.fda_adjacent": "false", "stealer.risk_tags": "multi_app_collection", "stealer.secrets_exported": "false"]),
            HardeningTestFixtures.event("TCCESFVISIBILITY", "tcc_esf.visibility", ["visibility.depth": "thin", "visibility.tcc_path_listable": "false", "visibility.tool_present": "false", "visibility.tool_path": "", "visibility.risk_tags": "thin_visibility,sensor_gap_adjacent"]),
        ]
        let findings = HardeningAssessment.assess(events: synthetic)
        assertWave8ControlFindings(findings)
        assertWave8NonGoals(findings)
    }

    func testHardeningAssessmentWave8OfflineWithRemediation() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let findings = try HardeningAssessment.assessOffline(source: .directory(relativeRoot))
        XCTAssertFalse(findings.isEmpty)
        let controls = Set(findings.map(\.control))
        for control in wave8HardenControls {
            XCTAssertTrue(controls.contains(control), "missing control \(control); have \(controls.sorted())")
        }
        let fails = findings.filter {
            wave8HardenControls.contains($0.control) && ($0.status == "fail" || $0.status == "warn")
        }
        XCTAssertFalse(fails.isEmpty)
        for f in fails {
            XCTAssertFalse(f.remediation.isEmpty, "empty remediation for \(f.control)")
        }
    }

    // MARK: - Detections

    func testWave8DetectionFixturesViaFixtureRunner() throws {
        let rulesDir = URL(fileURLWithPath: "Content/detections/samples")
        let fixturesDir = rulesDir.appendingPathComponent("fixtures")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: rulesDir.path))

        let wave8Rules = [
            "packagekit_installer_design.yaml",
            "archive_quarantine_extractor.yaml",
            "infostealer_path_plane.yaml",
            "tcc_esf_visibility_depth.yaml",
        ]
        var hitIDs: [String] = []
        for name in wave8Rules {
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
        // Evidence print for CLI log capture when run with --filter
        print("WAVE8_DETECTION_RULE_IDS=\(hitIDs.joined(separator: ","))")
        print("WAVE8_HARDEN_CONTROLS=\(wave8HardenControls.joined(separator: ","))")
    }

    func testMissingMarkersReturnEmpty() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("wave8-empty-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }
        XCTAssertEqual(try PackageKitDesignParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try ArchiveExtractorParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try InfoStealerPathParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try TCCESFVisibilityParser().parse(source: .directory(tmp)).count, 0)
    }

    func testPrintWave8ControlsForEvidence() {
        let synthetic: [EventEnvelope] = [
            parserEvent("packagekit.design", "PACKAGEKITDESIGN", ["packagekit.service_present": "true", "packagekit.receipt_paths": "/Library/Receipts", "packagekit.risk_tags": "design_surface"]),
            parserEvent("archive.extractor", "ARCHIVEEXTRACTOR", ["archive.extractor_name": "Keka", "archive.third_party": "true", "archive.risk_tags": "third_party_extractor"]),
            parserEvent("stealer.path", "INFOSTEALERPATH", ["stealer.path_family": "browser", "stealer.path": "/Users/alice/Library/Safari", "stealer.fda_adjacent": "true", "stealer.risk_tags": "multi_app_collection,fda_adjacent"]),
            parserEvent("tcc_esf.visibility", "TCCESFVISIBILITY", ["visibility.depth": "thin", "visibility.risk_tags": "thin_visibility"]),
        ]
        let findings = HardeningAssessment.assess(events: synthetic)
        let controls = findings
            .filter { wave8HardenControls.contains($0.control) }
            .map { "\($0.control):\($0.status):\($0.severity)" }
        print("WAVE8_HARDEN_FINDINGS=\(controls.joined(separator: ";"))")
        XCTAssertEqual(Set(findings.map(\.control)).intersection(Set(wave8HardenControls)).count, 4)
    }

    private func parserEvent(_ kind: String, _ label: String, _ properties: [String: String]) -> EventEnvelope {
        EventEnvelope(identity: .init(kind: kind, label: label), capture: .init(source: .parser), payload: .init(properties: properties))
    }
}
