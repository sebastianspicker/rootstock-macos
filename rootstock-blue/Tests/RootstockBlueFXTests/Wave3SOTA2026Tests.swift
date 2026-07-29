import XCTest
@testable import RootstockBlueFX
@testable import RootstockBlueCore
@testable import RootstockBlueCase
@testable import RootstockBlueDetect

/// Wave-3 2026 coverage expansion beyond shipped §7.1–§7.2:
/// SHELLPROFILES, EMOND, SUDOERS, LAUNCHDOVERRIDES + HardeningAssessment.
final class Wave3SOTA2026Tests: XCTestCase {
    var relativeRoot: URL {
        URL(fileURLWithPath: "Fixtures/artifacts/macos_sample")
    }

    var absoluteRoot: URL {
        relativeRoot.standardizedFileURL.resolvingSymlinksInPath()
    }

    // MARK: - Runtime registration

    func testPluginRuntimeIncludesWave3Parsers() {
        let ids = Set(PluginRuntime().parserIDs())
        for id in ["SHELLPROFILES", "EMOND", "SUDOERS", "LAUNCHDOVERRIDES"] {
            XCTAssertTrue(ids.contains(id), "defaultTier1 missing wave-3 parser \(id)")
        }
        // Regression: prior expansion still present
        for id in ["CRON", "BIOME", "BTM", "UTMPX", "GATEKEEPER"] {
            XCTAssertTrue(ids.contains(id), "regression: missing prior family \(id)")
        }
    }

    // MARK: - SHELLPROFILES

    func testShellProfilesParserEmitsDyldAndCurlRisk() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try ShellProfilesParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "expected shell profile events")
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "SHELLPROFILES" })
        XCTAssertTrue(events.allSatisfy { $0.eventType == "persistence.item" })

        let riskTags = events.compactMap { $0.fields["persistence.risk_tags"] }.joined(separator: ",")
        XCTAssertTrue(riskTags.contains("dyld_insert"), "expected dyld_insert risk, got \(riskTags)")
        XCTAssertTrue(riskTags.contains("curl_pipe_shell"), "expected curl_pipe_shell risk, got \(riskTags)")

        let cmds = events.compactMap { $0.fields["persistence.command"] }.joined(separator: "\n")
        XCTAssertTrue(cmds.contains("DYLD_INSERT_LIBRARIES") || cmds.lowercased().contains("dyld"), cmds)
        XCTAssertTrue(events.contains { $0.fields["persistence.kind"] == "shell_profile" })
        XCTAssertTrue(events.contains { $0.fields[FieldTaxonomy.userName] == "alice" })
    }

    // MARK: - EMOND

    func testEmondParserEmitsTmpPayloadRule() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try EmondParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "expected emond events")
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "EMOND" })
        let cmds = events.compactMap { $0.fields["persistence.command"] }.joined(separator: " ")
        XCTAssertTrue(cmds.contains("/tmp/"), "expected /tmp emond payload, got \(cmds)")
        XCTAssertTrue(events.contains { $0.fields["persistence.kind"] == "emond" })
        XCTAssertTrue(events.contains {
            ($0.fields["emond.rule_name"] ?? $0.fields["persistence.label"] ?? "").contains("evil")
        })
    }

    // MARK: - SUDOERS

    func testSudoersParserEmitsNopasswdGrant() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try SudoersParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "expected sudoers events")
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "SUDOERS" })
        XCTAssertTrue(events.allSatisfy { $0.eventType == "privilege.sudoers" })

        let nopasswd = events.filter {
            ($0.fields["privilege.risk_tags"] ?? "").contains("nopasswd")
        }
        XCTAssertFalse(nopasswd.isEmpty, "expected NOPASSWD risk tags")
        let lines = nopasswd.compactMap { $0.fields["privilege.line"] }.joined(separator: "\n")
        XCTAssertTrue(lines.uppercased().contains("NOPASSWD"), lines)
    }

    // MARK: - LAUNCHDOVERRIDES

    func testLaunchdOverridesParserEmitsSecurityDisabled() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try LaunchdOverridesParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "expected launchd override events")
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "LAUNCHDOVERRIDES" })
        XCTAssertTrue(events.allSatisfy { $0.eventType == "defense.launchd_override" })

        let securityDisabled = events.filter {
            $0.fields["defense.disabled"] == "true"
                && $0.fields["defense.security_product_hint"] == "true"
        }
        XCTAssertFalse(securityDisabled.isEmpty, "expected security product disabled (Santa/Falcon)")
        let labels = securityDisabled.compactMap { $0.fields["defense.label"] }.joined(separator: " ")
        XCTAssertTrue(
            labels.lowercased().contains("santa") || labels.lowercased().contains("falcon"),
            "expected santa/falcon in \(labels)"
        )
    }

    // MARK: - Engine + parity

    func testForensicsEngineEmitsWave3Plugins() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try ForensicsEngine().parse(source: .directory(relativeRoot))
        let plugins = Set(events.map(\.sourcePlugin))
        for id in ["SHELLPROFILES", "EMOND", "SUDOERS", "LAUNCHDOVERRIDES"] {
            XCTAssertTrue(plugins.contains(id), "engine missing events from \(id); have \(plugins.sorted())")
        }
    }

    func testRelativeAbsoluteParityWave3() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let parsers: [any ArtifactParser] = [
            ShellProfilesParser(),
            EmondParser(),
            SudoersParser(),
            LaunchdOverridesParser(),
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

    // MARK: - Hardening assessment

    func testHardeningAssessmentOfflineProducesRemediation() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let findings = try HardeningAssessment.assessOffline(source: .directory(relativeRoot))
        XCTAssertFalse(findings.isEmpty, "expected hardening findings")

        // Fixture security_posture.json has SIP/firewall/gatekeeper/FV degraded
        let sip = findings.first { $0.control == "sip" }
        XCTAssertNotNil(sip, "expected SIP finding")
        XCTAssertEqual(sip?.status, "fail")
        XCTAssertFalse(sip?.remediation.isEmpty ?? true, "SIP remediation must be non-empty")

        let fw = findings.first { $0.control == "firewall" }
        XCTAssertNotNil(fw)
        XCTAssertEqual(fw?.status, "fail")
        XCTAssertTrue(fw?.remediation.lowercased().contains("firewall") ?? false)

        // Wave-3 signal-driven findings
        XCTAssertTrue(
            findings.contains { $0.control == "sudoers_nopasswd" && $0.status == "fail" },
            "expected sudoers NOPASSWD finding: \(findings.map(\.control))"
        )
        XCTAssertTrue(
            findings.contains { $0.control == "shell_profile_risk" && $0.status == "fail" },
            "expected shell profile risk finding"
        )
        XCTAssertTrue(
            findings.contains { $0.control == "launchd_security_disabled" && $0.status == "fail" },
            "expected launchd security disabled finding"
        )
        XCTAssertTrue(
            findings.contains { $0.control == "emond_rules" },
            "expected emond findings"
        )

        // toEvents must carry remediation into case fields
        let events = HardeningAssessment.toEvents(findings, mode: "offline")
        XCTAssertEqual(events.count, findings.count)
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "HARDEN" })
        XCTAssertTrue(events.allSatisfy { $0.eventType == "harden.finding" })
        XCTAssertTrue(events.contains { !($0.fields["harden.remediation"] ?? "").isEmpty })
    }

    func testHardeningAssessmentPureFromSyntheticEvents() {
        // Pure unit path - no filesystem: drive assess(events:) with synthetic posture
        let degraded = [
            EventEnvelope(
                identity: EventEnvelope.Identity(
                    kind: "ir.posture.protection",
                    label: "IRPOSTURE"
                ),
                capture: EventEnvelope.Capture(
                    source: .collect
                ),
                payload: EventEnvelope.Payload(
                    properties: [
                    "protection.name": "SIP",
                    "protection.enabled": "false",
                    "protection.raw": "disabled",
                ]
                )
            ),
            EventEnvelope(
                identity: EventEnvelope.Identity(
                    kind: "ir.posture.protection",
                    label: "IRPOSTURE"
                ),
                capture: EventEnvelope.Capture(
                    source: .collect
                ),
                payload: EventEnvelope.Payload(
                    properties: [
                    "protection.name": "Firewall",
                    "protection.enabled": "false",
                ]
                )
            ),
        ]
        let findings = HardeningAssessment.assess(events: degraded)
        XCTAssertTrue(findings.contains { $0.control == "sip" && $0.status == "fail" })
        XCTAssertTrue(findings.contains { $0.control == "firewall" && $0.status == "fail" })
        let sip = findings.first { $0.control == "sip" }!
        XCTAssertTrue(sip.remediation.contains("csrutil") || sip.remediation.lowercased().contains("sip"))
    }

    func testHardeningWriteToCaseAndCustody() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("wave3-harden-\(UUID().uuidString).rsbcase")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let pkg = try CasePackage.create(at: tmp, name: "wave3-harden")
        let findings = try HardeningAssessment.assessOffline(source: .directory(relativeRoot))
        let n = try HardeningAssessment.writeToCase(findings, package: pkg, mode: "offline")
        XCTAssertGreaterThan(n, 0)
        let events = try pkg.loadAllEvents()
        XCTAssertTrue(events.contains { $0.sourcePlugin == "HARDEN" && $0.eventType == "harden.finding" })
        let custody = try String(contentsOf: pkg.custodyURL, encoding: .utf8)
        XCTAssertTrue(custody.contains("harden_assess"), custody)
    }

    // MARK: - Inventory merge + detect

    func testPersistenceInventoryIncludesShellAndEmond() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let inv = try PersistenceInventory.enumerate(source: .directory(relativeRoot))
        XCTAssertFalse(inv.isEmpty)
        let sources = Set(inv.compactMap { $0.fields["inventory.source"] })
        XCTAssertTrue(sources.contains("shell_profile"), "inventory sources: \(sources)")
        XCTAssertTrue(sources.contains("emond"), "inventory sources: \(sources)")
        // Prior sources still present
        XCTAssertTrue(sources.contains("cron") || sources.contains("autostart") || sources.contains("btm"))
    }

    func testParseIntoCaseDetectsWave3Signals() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("wave3-case-\(UUID().uuidString).rsbcase")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let pkg = try CasePackage.create(at: tmp, name: "wave3")
        let n = try ForensicsEngine().parse(source: .directory(relativeRoot), into: pkg)
        XCTAssertGreaterThan(n, 0)

        let posture = try HostIRPosture.enumerateOffline(source: .directory(relativeRoot))
        _ = try HostIRPosture.writeToCase(posture, package: pkg, mode: "offline")

        let harden = try HardeningAssessment.assessOffline(source: .directory(relativeRoot))
        _ = try HardeningAssessment.writeToCase(harden, package: pkg, mode: "offline")

        let inv = try PersistenceInventory.enumerate(source: .directory(relativeRoot))
        _ = try PersistenceInventory.writeToCase(inv, package: pkg)

        let timeline = try CaseTimeline.merged(from: pkg)
        XCTAssertFalse(timeline.isEmpty)
        let plugins = Set(timeline.map(\.sourcePlugin))
        XCTAssertTrue(plugins.contains("SHELLPROFILES"))
        XCTAssertTrue(plugins.contains("EMOND"))
        XCTAssertTrue(plugins.contains("SUDOERS"))
        XCTAssertTrue(plugins.contains("LAUNCHDOVERRIDES"))
        XCTAssertTrue(plugins.contains("HARDEN"))

        let rulesDir = URL(fileURLWithPath: "Content/detections/samples")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: rulesDir.path))
        let findings = try DetectionEngine().evaluate(rulesDirectory: rulesDir, events: timeline)
        let ids = Set(findings.map(\.ruleID))
        let wave3Hits = ids.filter {
            $0.contains("shell_profile") || $0.contains("emond") || $0.contains("sudoers")
                || $0.contains("launchd_security") || $0.contains("harden_sip")
        }
        XCTAssertFalse(
            wave3Hits.isEmpty,
            "expected wave-3 detection hits from real timeline, got rule ids: \(ids.sorted())"
        )
    }

    func testWave3DetectionFixturesViaFixtureRunner() throws {
        let rulesDir = URL(fileURLWithPath: "Content/detections/samples")
        let fixturesDir = rulesDir.appendingPathComponent("fixtures")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: rulesDir.path))

        let wave3Rules = [
            "shell_profile_dyld_insert.yaml",
            "shell_profile_curl_pipe.yaml",
            "emond_tmp_payload.yaml",
            "sudoers_nopasswd.yaml",
            "launchd_security_disabled.yaml",
            "harden_sip_disabled.yaml",
        ]
        for name in wave3Rules {
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
        }
    }
}
