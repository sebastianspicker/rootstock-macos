import XCTest
@testable import RootstockBlueFX
@testable import RootstockBlueCore
@testable import RootstockBlueCase
@testable import RootstockBlueDetect

/// Wave-4 2026 coverage expansion beyond shipped §7.1–§7.9:
/// PRIVHELPERS, FOLDERACTIONS, LOGINHOOKS + access-posture harden controls.
final class Wave4SOTA2026Tests: XCTestCase {
    var relativeRoot: URL {
        URL(fileURLWithPath: "Fixtures/artifacts/macos_sample")
    }

    var absoluteRoot: URL {
        relativeRoot.standardizedFileURL.resolvingSymlinksInPath()
    }

    // MARK: - Runtime registration

    func testPluginRuntimeIncludesWave4Parsers() {
        let ids = Set(PluginRuntime().parserIDs())
        for id in ["PRIVHELPERS", "FOLDERACTIONS", "LOGINHOOKS"] {
            XCTAssertTrue(ids.contains(id), "defaultTier1 missing wave-4 parser \(id)")
        }
        // Regression: Wave-3 still present
        for id in ["SHELLPROFILES", "EMOND", "SUDOERS", "LAUNCHDOVERRIDES"] {
            XCTAssertTrue(ids.contains(id), "regression: missing wave-3 family \(id)")
        }
    }

    // MARK: - PRIVHELPERS

    func testPrivHelpersParserEmitsUnknownHelper() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try PrivHelpersParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "expected privileged helper events")
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "PRIVHELPERS" })
        XCTAssertTrue(events.allSatisfy { $0.eventType == "persistence.item" })
        XCTAssertTrue(events.contains { $0.fields["persistence.kind"] == "privileged_helper" })

        let labels = events.compactMap { $0.fields["privhelper.label"] ?? $0.fields["persistence.label"] }.joined(separator: " ")
        XCTAssertTrue(labels.contains("evil") || labels.contains("privhelper"), "labels=\(labels)")

        let risk = events.compactMap { $0.fields["persistence.risk_tags"] }.joined(separator: ",")
        XCTAssertTrue(
            risk.contains("unknown_team") || risk.contains("orphan") || labels.lowercased().contains("evil"),
            "expected risk tags or evil helper, got risk=\(risk) labels=\(labels)"
        )

        // Entity identity non-empty
        XCTAssertTrue(events.contains { !$0.entityRefs.isEmpty })
        XCTAssertTrue(events.contains { !($0.fields[FieldTaxonomy.filePath] ?? "").isEmpty })
    }

    // MARK: - FOLDERACTIONS

    func testFolderActionsParserEmitsDoShellDownloads() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try FolderActionsParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "expected folder action events")
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "FOLDERACTIONS" })
        XCTAssertTrue(events.contains { $0.fields["persistence.kind"] == "folder_action" })

        let risk = events.compactMap {
            $0.fields["persistence.risk_tags"] ?? $0.fields["folder_action.risk_tags"]
        }.joined(separator: ",")
        XCTAssertTrue(
            risk.contains("do_shell_script") || risk.contains("downloads_watch") || risk.contains("network_fetch"),
            "expected FA risk tags, got \(risk)"
        )
        XCTAssertTrue(events.contains {
            ($0.fields["folder_action.watched_path"] ?? "").lowercased().contains("download")
                || ($0.fields["persistence.command"] ?? "").contains("Folder Action")
        })
        // Alice fixture ownership (not host user from absolute path prefix)
        let aliceEvents = events.filter {
            ($0.fields["persistence.command"] ?? "").contains("evil-folder-action")
                || ($0.fields["folder_action.name"] ?? "").contains("evil")
                || ($0.fields["folder_action.script_path"] ?? "").contains("evil-folder-action")
        }
        XCTAssertFalse(aliceEvents.isEmpty, "expected evil-folder-action fixture events")
        XCTAssertTrue(
            aliceEvents.contains { $0.fields[FieldTaxonomy.userName] == "alice" },
            "expected user.name=alice for alice fixture, got \(aliceEvents.map { $0.fields[FieldTaxonomy.userName] ?? "?" })"
        )
        XCTAssertTrue(
            aliceEvents.contains {
                $0.entityRefs.contains { $0.value.contains("|alice|") || $0.value.contains("alice") }
            },
            "expected entity identity containing alice"
        )
    }

    // MARK: - LOGINHOOKS

    func testLoginHooksParserEmitsLoginLogoutHooks() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try LoginHooksParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "expected login hook events")
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "LOGINHOOKS" })
        XCTAssertTrue(events.contains {
            $0.fields["persistence.kind"] == "login_hook" || $0.fields["persistence.kind"] == "logout_hook"
        })
        let paths = events.compactMap { $0.fields["loginwindow.script_path"] ?? $0.fields["persistence.command"] }.joined(separator: " ")
        XCTAssertTrue(paths.contains("evil") || paths.contains("/tmp/"), "hooks=\(paths)")
        XCTAssertTrue(events.contains { $0.fields["loginwindow.hook_type"] == "login" })
    }

    // MARK: - Engine + parity

    func testForensicsEngineEmitsWave4Plugins() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try ForensicsEngine().parse(source: .directory(relativeRoot))
        let plugins = Set(events.map(\.sourcePlugin))
        for id in ["PRIVHELPERS", "FOLDERACTIONS", "LOGINHOOKS"] {
            XCTAssertTrue(plugins.contains(id), "engine missing events from \(id); have \(plugins.sorted())")
        }
    }

    func testRelativeAbsoluteParityWave4() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let parsers: [any ArtifactParser] = [
            PrivHelpersParser(),
            FolderActionsParser(),
            LoginHooksParser(),
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

        // Absolute roots under /Users/<host>/.../Users/alice must still attribute to alice
        let relFA = try FolderActionsParser().parse(source: .directory(relativeRoot))
        let absFA = try FolderActionsParser().parse(source: .directory(absoluteRoot))
        func aliceFixture(_ events: [EventEnvelope]) -> [EventEnvelope] {
            events.filter {
                ($0.fields["folder_action.script_path"] ?? $0.fields["persistence.command"] ?? "")
                    .contains("evil-folder-action")
                    || ($0.fields["folder_action.name"] ?? "").contains("evil")
            }
        }
        let relAlice = aliceFixture(relFA)
        let absAlice = aliceFixture(absFA)
        XCTAssertFalse(relAlice.isEmpty)
        XCTAssertFalse(absAlice.isEmpty)
        XCTAssertTrue(
            relAlice.allSatisfy { $0.fields[FieldTaxonomy.userName] == "alice" },
            "relative root user.name: \(relAlice.map { $0.fields[FieldTaxonomy.userName] ?? "?" })"
        )
        XCTAssertTrue(
            absAlice.allSatisfy { $0.fields[FieldTaxonomy.userName] == "alice" },
            "absolute root must not use host user; got \(absAlice.map { $0.fields[FieldTaxonomy.userName] ?? "?" })"
        )
        XCTAssertTrue(
            absAlice.allSatisfy { e in
                e.entityRefs.contains { $0.value.contains("|alice|") || $0.value.hasPrefix("folder_action|alice") }
            },
            "absolute entity refs must contain |alice|, got \(absAlice.flatMap(\.entityRefs).map(\.value))"
        )
    }

    // MARK: - Hardening assessment Wave-4

    func testHardeningAssessmentWave4ControlsWithRemediation() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let findings = try HardeningAssessment.assessOffline(source: .directory(relativeRoot))
        XCTAssertFalse(findings.isEmpty)

        let controls = Set(findings.map(\.control))
        // Wave-4 persistence-driven
        XCTAssertTrue(controls.contains("privileged_helper_unknown"), "controls=\(controls)")
        XCTAssertTrue(controls.contains("folder_action_risky"), "controls=\(controls)")
        XCTAssertTrue(controls.contains("login_hook_present"), "controls=\(controls)")
        // Wave-4 access posture
        XCTAssertTrue(controls.contains("remote_login"), "controls=\(controls)")
        XCTAssertTrue(controls.contains("guest_account") || controls.contains("auto_login"), "controls=\(controls)")
        XCTAssertTrue(controls.contains("file_sharing"), "controls=\(controls)")
        XCTAssertTrue(controls.contains("software_update_catalog") || controls.contains("software_update_auto"), "controls=\(controls)")
        XCTAssertTrue(controls.contains("lockdown_mode"), "controls=\(controls)")

        // Every fail must carry remediation
        let fails = findings.filter { $0.status == "fail" }
        XCTAssertFalse(fails.isEmpty)
        for f in fails {
            XCTAssertFalse(f.remediation.isEmpty, "empty remediation for \(f.control)")
        }

        // Regression: Wave-3 still assessed
        XCTAssertTrue(controls.contains("sip") || controls.contains("sudoers_nopasswd") || controls.contains("shell_profile_risk"))
    }

    func testHardeningWave4PureFromSyntheticEvents() {
        let synthetic = [
            HardeningTestFixtures.event("LOGINHOOKS", "persistence.item", ["persistence.kind": "login_hook", "loginwindow.hook_type": "login", "loginwindow.script_path": "/tmp/hook.sh", "persistence.command": "/tmp/hook.sh"]),
            HardeningTestFixtures.event("IRPOSTURE", "ir.posture.remote_access", ["protection.name": "RemoteLogin", "protection.enabled": "true", "remote.service": "ssh", "remote.enabled": "true"]),
            HardeningTestFixtures.event("IRPOSTURE", "ir.posture.account", ["account.kind": "guest", "account.enabled": "true", "account.guest_enabled": "true"]),
            HardeningTestFixtures.event("IRPOSTURE", "ir.posture.software_update", ["protection.name": "SoftwareUpdateCatalog", "su.catalog_url": "https://evil.example/catalog", "su.catalog_non_apple": "true"]),
        ]
        let findings = HardeningAssessment.assess(events: synthetic)
        for control in ["login_hook_present", "remote_login", "guest_account", "software_update_catalog"] {
            XCTAssertTrue(findings.contains { $0.control == control && $0.status == "fail" })
        }
        let login = findings.first { $0.control == "login_hook_present" }!
        XCTAssertTrue(login.remediation.lowercased().contains("login") || login.remediation.contains("defaults"))
    }

    func testHardeningWriteToCaseWave4() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("wave4-harden-\(UUID().uuidString).rsbcase")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let pkg = try CasePackage.create(at: tmp, name: "wave4-harden")
        let findings = try HardeningAssessment.assessOffline(source: .directory(relativeRoot))
        let n = try HardeningAssessment.writeToCase(findings, package: pkg, mode: "offline")
        XCTAssertGreaterThan(n, 0)
        let events = try pkg.loadAllEvents()
        XCTAssertTrue(events.contains {
            $0.sourcePlugin == "HARDEN"
                && ($0.fields["harden.control"] == "login_hook_present"
                    || $0.fields["harden.control"] == "remote_login"
                    || $0.fields["harden.control"] == "privileged_helper_unknown")
        })
        let custody = try String(contentsOf: pkg.custodyURL, encoding: .utf8)
        XCTAssertTrue(custody.contains("harden_assess"), custody)
    }

    // MARK: - Inventory merge

    func testPersistenceInventoryIncludesWave4Sources() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let inv = try PersistenceInventory.enumerate(source: .directory(relativeRoot))
        XCTAssertFalse(inv.isEmpty)
        let sources = Set(inv.compactMap { $0.fields["inventory.source"] })
        XCTAssertTrue(sources.contains("privileged_helper"), "inventory sources: \(sources)")
        XCTAssertTrue(sources.contains("folder_action"), "inventory sources: \(sources)")
        XCTAssertTrue(sources.contains("login_hook"), "inventory sources: \(sources)")
        // Prior sources still present
        XCTAssertTrue(sources.contains("shell_profile") || sources.contains("emond") || sources.contains("cron"))
    }

    // MARK: - Full shipped path: parse → posture → harden → inventory → detect

    func testParseIntoCaseDetectsWave4Signals() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("wave4-case-\(UUID().uuidString).rsbcase")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let pkg = try CasePackage.create(at: tmp, name: "wave4")
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
        XCTAssertTrue(plugins.contains("PRIVHELPERS"))
        XCTAssertTrue(plugins.contains("FOLDERACTIONS"))
        XCTAssertTrue(plugins.contains("LOGINHOOKS"))
        XCTAssertTrue(plugins.contains("HARDEN"))

        let rulesDir = URL(fileURLWithPath: "Content/detections/samples")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: rulesDir.path))
        let findings = try DetectionEngine().evaluate(rulesDirectory: rulesDir, events: timeline)
        let ids = Set(findings.map(\.ruleID))
        let wave4Hits = ids.filter {
            $0.contains("privhelper") || $0.contains("folder_action") || $0.contains("login_hook")
                || $0.contains("remote_login") || $0.contains("guest_or_autologin")
                || $0.contains("su_catalog") || $0.contains("autologin")
        }
        XCTAssertFalse(
            wave4Hits.isEmpty,
            "expected wave-4 detection hits from real timeline, got rule ids: \(ids.sorted())"
        )
    }

    func testWave4DetectionFixturesViaFixtureRunner() throws {
        let rulesDir = URL(fileURLWithPath: "Content/detections/samples")
        let fixturesDir = rulesDir.appendingPathComponent("fixtures")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: rulesDir.path))

        let wave4Rules = [
            "privhelper_unknown_team.yaml",
            "folder_action_do_shell.yaml",
            "login_hook_set.yaml",
            "remote_login_enabled.yaml",
            "guest_or_autologin.yaml",
            "su_catalog_non_apple.yaml",
        ]
        for name in wave4Rules {
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

    func testIRPostureEmitsWave4AccessSurfaces() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try HostIRPosture.enumerateOffline(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty)

        let remoteServices = events.compactMap { $0.fields["remote.service"] ?? $0.fields["protection.name"] }
        XCTAssertTrue(
            remoteServices.contains { $0.lowercased().contains("ssh") || $0.lowercased().contains("remotelogin") },
            "expected remote login signal: \(remoteServices)"
        )
        XCTAssertTrue(
            events.contains { $0.eventType == "ir.posture.account" || $0.fields["account.guest_enabled"] == "true" || $0.fields["account.auto_login_enabled"] == "true" },
            "expected account posture"
        )
        XCTAssertTrue(
            events.contains { $0.fields["su.catalog_non_apple"] == "true" || ($0.fields["su.catalog_url"] ?? "").contains("evil") },
            "expected software update catalog signal"
        )
    }
}
