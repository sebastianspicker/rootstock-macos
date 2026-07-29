import XCTest
@testable import RootstockBlueFX
@testable import RootstockBlueCore
@testable import RootstockBlueCase
@testable import RootstockBlueDetect

/// Wave-6 2026 coverage expansion beyond shipped §7.1–§7.11:
/// SPOTLIGHT, TRASH, DOCREVISIONS, SAVEDSTATE, FIREFOX, NOTIFICATIONS,
/// QUICKLOOK, SCREENTIME, ICLOUD + harden controls with remediation.
final class Wave6SOTA2026Tests: XCTestCase {
    var relativeRoot: URL {
        URL(fileURLWithPath: "Fixtures/artifacts/macos_sample")
    }

    var absoluteRoot: URL {
        relativeRoot.standardizedFileURL.resolvingSymlinksInPath()
    }

    private let wave6IDs = [
        "SPOTLIGHT", "TRASH", "DOCREVISIONS", "SAVEDSTATE", "FIREFOX",
        "NOTIFICATIONS", "QUICKLOOK", "SCREENTIME", "ICLOUD",
    ]

    private let wave6HardenControls = [
        "trash_sensitive_artifact",
        "spotlight_sensitive_index",
        "firefox_suspicious_download",
        "notification_sensitive_marker",
        "quicklook_sensitive_cache",
        "screentime_suspicious_app",
        "icloud_desktop_documents_sync",
        "saved_state_suspicious_app",
    ]

    // MARK: - Runtime registration

    func testPluginRuntimeIncludesWave6Parsers() {
        let ids = Set(PluginRuntime().parserIDs())
        for id in wave6IDs {
            XCTAssertTrue(ids.contains(id), "defaultTier1 missing wave-6 parser \(id)")
        }
        // Regression: Wave-5 still present
        for id in ["AUTHPLUGINS", "NETUSAGE", "USBHISTORY", "KEYCHAINMETA", "CODESIGN", "ARD"] {
            XCTAssertTrue(ids.contains(id), "regression: missing wave-5 family \(id)")
        }
        // Regression: Wave-4 still present
        for id in ["PRIVHELPERS", "FOLDERACTIONS", "LOGINHOOKS"] {
            XCTAssertTrue(ids.contains(id), "regression: missing wave-4 family \(id)")
        }
    }

    // MARK: - Family parsers

    func testSpotlightParserEmitsSensitiveIndex() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try SpotlightParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "expected spotlight events")
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "SPOTLIGHT" })
        XCTAssertTrue(events.contains { $0.eventType == "filesystem.spotlight" })
        let risk = events.compactMap { $0.fields["spotlight.risk_tags"] }.joined(separator: ",")
        let paths = events.compactMap { $0.fields["spotlight.path"] }.joined(separator: " ")
        XCTAssertTrue(
            risk.contains("sensitive") || risk.contains("credential") || paths.contains("password"),
            "risk=\(risk) paths=\(paths)"
        )
        XCTAssertTrue(events.contains { !$0.entityRefs.isEmpty })
    }

    func testTrashParserEmitsSensitiveRecovery() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try TrashParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "expected trash events")
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "TRASH" })
        XCTAssertTrue(events.contains { $0.eventType == "filesystem.trash" })
        let risk = events.compactMap { $0.fields["trash.risk_tags"] }.joined(separator: ",")
        let names = events.compactMap { $0.fields["trash.filename"] }.joined(separator: " ")
        XCTAssertTrue(
            risk.contains("credential") || risk.contains("sensitive") || names.contains("id_rsa")
                || names.contains("evil"),
            "risk=\(risk) names=\(names)"
        )
        // Non-goal: fields must not dump private key PEM bodies
        for e in events {
            let joined = e.fields.values.joined(separator: " ").lowercased()
            XCTAssertFalse(joined.contains("-----begin"), "must not dump key material: \(e.fields)")
        }
    }

    /// Regression: walked .Trash files under /Users/<dev>/…/Fixtures/…/Users/alice must
    /// attribute user.name=alice (last Users segment) and emit image-relative trash_path.
    private func isAliceFixtureTrashEvent(_ event: EventEnvelope) -> Bool {
        let fields = event.fields
        return (fields["trash.original_path"] ?? "").contains("alice")
            || (fields["trash.trash_path"] ?? "").contains("alice")
            || (fields["trash.filename"] ?? "").contains("evil")
            || (fields["trash.filename"] ?? "") == "id_rsa"
    }

    func testTrashParserUserAndPathNotHostDeveloper() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: absoluteRoot.path))
        let events = try TrashParser().parse(source: .directory(absoluteRoot))
        XCTAssertFalse(events.isEmpty)
        let hostUser = NSUserName()
        for event in events {
            if let user = event.fields[FieldTaxonomy.userName], !user.isEmpty {
                XCTAssertNotEqual(user, hostUser, "trash user.name must not be host developer \(hostUser); event=\(event.fields)")
                if isAliceFixtureTrashEvent(event) {
                    XCTAssertEqual(user, "alice", "expected alice for fixture trash row: \(event.fields)")
                }
            }
            let trashPath = event.fields["trash.trash_path"] ?? ""
            XCTAssertFalse(trashPath.contains("/Git/mac-security-research"), "trash_path must be image-relative, not host-absolute: \(trashPath)")
            XCTAssertFalse(trashPath.hasPrefix("/Users/\(hostUser)/"), "trash_path must not start with host home: \(trashPath)")
        }
        let aliceRows = events.filter(isAliceFixtureTrashEvent)
        XCTAssertFalse(aliceRows.isEmpty)
        for event in aliceRows {
            XCTAssertEqual(event.fields[FieldTaxonomy.userName], "alice", "alice fixture row user: \(event.fields)")
        }
    }

    func testDocRevisionsParserEmitsVersions() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try DocRevisionsParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "expected doc revision events")
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "DOCREVISIONS" })
        XCTAssertTrue(events.contains { $0.eventType == "filesystem.doc_revision" })
        XCTAssertTrue(events.contains {
            !($0.fields["docrev.path"] ?? "").isEmpty || $0.fields["docrev.marker"] == "true"
        })
    }

    func testSavedStateParserEmitsSuspiciousBundle() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try SavedStateParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "expected saved state events")
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "SAVEDSTATE" })
        XCTAssertTrue(events.contains { $0.eventType == "app.saved_state" })
        let risk = events.compactMap { $0.fields["savedstate.risk_tags"] }.joined(separator: ",")
        let bundles = events.compactMap { $0.fields["savedstate.bundle_id"] }.joined(separator: " ")
        XCTAssertTrue(
            risk.contains("suspicious") || risk.contains("tmp_path") || bundles.contains("evil"),
            "risk=\(risk) bundles=\(bundles)"
        )
    }

    func testFirefoxParserEmitsVisitsAndDownloads() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try FirefoxParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "expected firefox events")
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "FIREFOX" })
        XCTAssertTrue(events.contains { $0.eventType == "browser.visit" })
        XCTAssertTrue(events.contains { $0.eventType == "browser.download" })
        XCTAssertTrue(events.allSatisfy { $0.fields["browser.engine"] == "firefox" })
        let risk = events.compactMap { $0.fields["browser.risk_tags"] }.joined(separator: ",")
        let urls = events.compactMap { $0.fields["browser.url"] }.joined(separator: " ")
        XCTAssertTrue(
            risk.contains("evil") || risk.contains("script") || urls.contains("evil"),
            "risk=\(risk) urls=\(urls)"
        )
    }

    /// Regression: absolute fixture root under /Users/<dev>/… must still set user.name=alice
    /// from Users/alice/Library/Application Support/Firefox/… (last Users segment).
    func testFirefoxParserUserIsAliceNotHostDeveloper() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: absoluteRoot.path))
        let events = try FirefoxParser().parse(source: .directory(absoluteRoot))
        XCTAssertFalse(events.isEmpty)
        let hostUser = NSUserName()
        for e in events {
            let user = e.fields[FieldTaxonomy.userName] ?? ""
            XCTAssertFalse(user.isEmpty, "firefox event missing user.name: \(e.fields)")
            XCTAssertEqual(user, "alice", "expected alice, got \(user) host=\(hostUser) fields=\(e.fields)")
            XCTAssertNotEqual(user, hostUser)
        }
    }

    /// Walk-only trash file (not in inventory JSON) must use image-relative path + last Users user.
    func testTrashWalkOnlyFileImageRelativePath() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("wave6-trash-walk-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let trashDir = tmp.appendingPathComponent("Users/bob/.Trash", isDirectory: true)
        try FileManager.default.createDirectory(at: trashDir, withIntermediateDirectories: true)
        let residual = trashDir.appendingPathComponent("unique-walk-only.bin")
        try Data("walk-only".utf8).write(to: residual)

        let events = try TrashParser().parse(source: .directory(tmp))
        let walk = events.filter { $0.fields["trash.filename"] == "unique-walk-only.bin" }
        XCTAssertEqual(walk.count, 1, "expected single walk-only trash event, got \(events)")
        let e = walk[0]
        XCTAssertEqual(e.fields[FieldTaxonomy.userName], "bob")
        let tp = e.fields["trash.trash_path"] ?? ""
        XCTAssertTrue(
            tp == "Users/bob/.Trash/unique-walk-only.bin" || tp.hasSuffix("Users/bob/.Trash/unique-walk-only.bin"),
            "expected image-relative trash_path, got \(tp)"
        )
        XCTAssertFalse(tp.contains(tmp.path), "must not embed host temp root: \(tp)")
    }

    func testNotificationsParserMetadataOnlyNoBody() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try NotificationsParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "expected notification events")
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "NOTIFICATIONS" })
        XCTAssertTrue(events.contains { $0.eventType == "notification.delivered" })
        for e in events {
            XCTAssertNil(e.fields["body"])
            XCTAssertNil(e.fields["notif.body"])
            XCTAssertNil(e.fields["message"])
            XCTAssertEqual(e.fields["notif.body_exported"], "false")
            let keys = e.fields.keys.map { $0.lowercased() }
            XCTAssertFalse(keys.contains("body"), "must not export body: \(e.fields)")
        }
        let risk = events.compactMap { $0.fields["notif.risk_tags"] }.joined(separator: ",")
        XCTAssertTrue(
            risk.contains("suspicious") || risk.contains("security_sensitive")
                || events.contains { ($0.fields["notif.app_id"] ?? "").contains("evil") },
            "risk=\(risk)"
        )
    }

    func testQuickLookParserEmitsSensitiveCache() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try QuickLookParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "expected quicklook events")
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "QUICKLOOK" })
        XCTAssertTrue(events.contains { $0.eventType == "filesystem.quicklook" })
        let risk = events.compactMap { $0.fields["ql.risk_tags"] }.joined(separator: ",")
        let paths = events.compactMap { $0.fields["ql.path"] }.joined(separator: " ")
        XCTAssertTrue(
            risk.contains("sensitive") || paths.contains("password") || paths.contains("evil")
                || events.contains { $0.fields["ql.marker"] == "true" },
            "risk=\(risk) paths=\(paths)"
        )
    }

    func testScreenTimeParserEmitsMarkers() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try ScreenTimeParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "expected screentime events")
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "SCREENTIME" })
        XCTAssertTrue(events.contains {
            $0.eventType == "pol.screentime" || $0.eventType == "pol.focus"
        })
        let risk = events.compactMap { $0.fields["screentime.risk_tags"] }.joined(separator: ",")
        let apps = events.compactMap { $0.fields["screentime.app_id"] }.joined(separator: " ")
        XCTAssertTrue(
            risk.contains("suspicious") || apps.contains("evil"),
            "risk=\(risk) apps=\(apps)"
        )
    }

    func testICloudParserEmitsSyncPosture() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try ICloudParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "expected icloud events")
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "ICLOUD" })
        XCTAssertTrue(events.contains { $0.eventType == "cloud.sync_posture" })
        XCTAssertTrue(events.contains { $0.fields["icloud.desktop_documents_sync"] == "true" })
        XCTAssertTrue(events.contains { $0.fields["icloud.drive_enabled"] == "true" })
    }

    // MARK: - Engine + parity

    func testForensicsEngineEmitsWave6Plugins() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try ForensicsEngine().parse(source: .directory(relativeRoot))
        let plugins = Set(events.map(\.sourcePlugin))
        for id in wave6IDs {
            XCTAssertTrue(plugins.contains(id), "engine missing events from \(id); have \(plugins.sorted())")
        }
    }

    func testRelativeAbsoluteParityWave6() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let parsers: [any ArtifactParser] = [
            SpotlightParser(),
            TrashParser(),
            DocRevisionsParser(),
            SavedStateParser(),
            FirefoxParser(),
            NotificationsParser(),
            QuickLookParser(),
            ScreenTimeParser(),
            ICloudParser(),
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

    // MARK: - Hardening

    func testHardeningAssessmentWave6ControlsWithRemediation() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let findings = try HardeningAssessment.assessOffline(source: .directory(relativeRoot))
        XCTAssertFalse(findings.isEmpty)

        let controls = Set(findings.map(\.control))
        for control in wave6HardenControls {
            XCTAssertTrue(controls.contains(control), "missing control \(control); have \(controls.sorted())")
        }

        let fails = findings.filter {
            wave6HardenControls.contains($0.control) && ($0.status == "fail" || $0.status == "warn")
        }
        XCTAssertFalse(fails.isEmpty)
        for f in fails {
            XCTAssertFalse(f.remediation.isEmpty, "empty remediation for \(f.control)")
        }

        // Regression: Wave-5 still assessed
        XCTAssertTrue(
            controls.contains("auth_plugin_unknown")
                || controls.contains("ard_all_local_users")
                || controls.contains("unsigned_persistence_binary")
        )
    }

    func testHardeningWave6PureFromSyntheticEvents() {
        let synthetic = [
            HardeningTestFixtures.event("TRASH", "filesystem.trash", ["trash.filename": "id_rsa", "trash.original_path": "/Users/alice/.ssh/id_rsa", "trash.risk_tags": "credential_material,sensitive_path"]),
            HardeningTestFixtures.event("SPOTLIGHT", "filesystem.spotlight", ["spotlight.path": "/Users/alice/Documents/secrets/passwords.txt", "spotlight.display_name": "passwords.txt", "spotlight.risk_tags": "sensitive_path,credential_filename"]),
            HardeningTestFixtures.event("FIREFOX", "browser.download", ["browser.engine": "firefox", "browser.url": "https://evil.example/payload.sh", "browser.download_path": "/Users/alice/Downloads/payload.sh", "browser.risk_tags": "script_download,evil_domain"]),
            HardeningTestFixtures.event("NOTIFICATIONS", "notification.delivered", ["notif.app_id": "com.evil.implant", "notif.title_marker": "Remote access granted", "notif.body_exported": "false", "notif.risk_tags": "suspicious_app,security_sensitive"]),
            HardeningTestFixtures.event("QUICKLOOK", "filesystem.quicklook", ["ql.path": "/Users/alice/Documents/secrets/passwords.txt", "ql.risk_tags": "sensitive_path,credential_filename"]),
            HardeningTestFixtures.event("SCREENTIME", "pol.screentime", ["screentime.app_id": "com.evil.implant", "screentime.bundle_path": "/tmp/evil-implant.app", "screentime.risk_tags": "suspicious_app,tmp_path"]),
            HardeningTestFixtures.event("ICLOUD", "cloud.sync_posture", ["icloud.desktop_documents_sync": "true", "icloud.drive_enabled": "true", "icloud.risk_tags": "desktop_documents_sync"]),
            HardeningTestFixtures.event("SAVEDSTATE", "app.saved_state", ["savedstate.bundle_id": "com.evil.implant", "savedstate.app_path": "/tmp/evil-implant.app", "savedstate.risk_tags": "suspicious_bundle,tmp_path"]),
        ]
        let findings = HardeningAssessment.assess(events: synthetic)
        for control in wave6HardenControls {
            XCTAssertTrue(findings.contains { $0.control == control && $0.status == "fail" }, "expected fail for \(control)")
            XCTAssertFalse(findings.first { $0.control == control }!.remediation.isEmpty, control)
        }
    }

    func testHardeningWriteToCaseWave6() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("wave6-harden-\(UUID().uuidString).rsbcase")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let pkg = try CasePackage.create(at: tmp, name: "wave6-harden")
        let findings = try HardeningAssessment.assessOffline(source: .directory(relativeRoot))
        let n = try HardeningAssessment.writeToCase(findings, package: pkg, mode: "offline")
        XCTAssertGreaterThan(n, 0)
        let events = try pkg.loadAllEvents()
        XCTAssertTrue(events.contains {
            $0.sourcePlugin == "HARDEN" && wave6HardenControls.contains($0.fields["harden.control"] ?? "")
        })
        let custody = try String(contentsOf: pkg.custodyURL, encoding: .utf8)
        XCTAssertTrue(custody.contains("harden_assess"), custody)
    }

    // MARK: - Inventory

    func testPersistenceInventoryIncludesSavedState() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let inv = try PersistenceInventory.enumerate(source: .directory(relativeRoot))
        XCTAssertFalse(inv.isEmpty)
        let sources = Set(inv.compactMap { $0.fields["inventory.source"] })
        XCTAssertTrue(
            sources.contains("saved_state"),
            "inventory sources: \(sources)"
        )
        // Prior wave sources still present
        XCTAssertTrue(
            sources.contains("authorization_plugin")
                || sources.contains("privileged_helper")
                || sources.contains("login_hook")
        )
    }

    // MARK: - Full shipped path

    func testParseIntoCaseDetectsWave6Signals() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("wave6-case-\(UUID().uuidString).rsbcase")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let pkg = try CasePackage.create(at: tmp, name: "wave6")
        XCTAssertGreaterThan(try ForensicsEngine().parse(source: .directory(relativeRoot), into: pkg), 0)
        let posture = try HostIRPosture.enumerateOffline(source: .directory(relativeRoot))
        _ = try HostIRPosture.writeToCase(posture, package: pkg, mode: "offline")
        let hardening = try HardeningAssessment.assessOffline(source: .directory(relativeRoot))
        _ = try HardeningAssessment.writeToCase(hardening, package: pkg, mode: "offline")
        let inventory = try PersistenceInventory.enumerate(source: .directory(relativeRoot))
        _ = try PersistenceInventory.writeToCase(inventory, package: pkg)
        let timeline = try CaseTimeline.merged(from: pkg)
        XCTAssertFalse(timeline.isEmpty)
        let plugins = Set(timeline.map(\.sourcePlugin))
        for id in wave6IDs { XCTAssertTrue(plugins.contains(id), "timeline missing \(id)") }
        XCTAssertTrue(plugins.contains("HARDEN"))
        let rulesDir = URL(fileURLWithPath: "Content/detections/samples")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: rulesDir.path))
        let ids = Set(try DetectionEngine().evaluate(rulesDirectory: rulesDir, events: timeline).map(\.ruleID))
        let fragments = ["trash", "spotlight", "firefox", "notification", "quicklook", "screentime", "icloud", "saved_state"]
        XCTAssertTrue(ids.contains { id in fragments.contains { id.contains($0) } }, "expected wave-6 detection hits from real timeline, got rule ids: \(ids.sorted())")
    }

    func testWave6DetectionFixturesViaFixtureRunner() throws {
        let rulesDir = URL(fileURLWithPath: "Content/detections/samples")
        let fixturesDir = rulesDir.appendingPathComponent("fixtures")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: rulesDir.path))

        let wave6Rules = [
            "trash_sensitive_artifact.yaml",
            "spotlight_sensitive_index.yaml",
            "firefox_suspicious_download.yaml",
            "notification_sensitive_marker.yaml",
            "quicklook_sensitive_cache.yaml",
            "screentime_suspicious_app.yaml",
            "icloud_desktop_documents_sync.yaml",
            "saved_state_suspicious_app.yaml",
        ]
        for name in wave6Rules {
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

    func testNonGoalNotificationsNoBodyExport() {
        let synthetic: [EventEnvelope] = [
            EventEnvelope(
                identity: EventEnvelope.Identity(
                    kind: "notification.delivered",
                    label: "NOTIFICATIONS"
                ),
                capture: EventEnvelope.Capture(
                    source: .parser
                ),
                payload: EventEnvelope.Payload(
                    properties: [
                    "notif.app_id": "com.evil.implant",
                    "notif.title_marker": "Remote access granted",
                    "notif.body_exported": "false",
                    "notif.risk_tags": "suspicious_app",
                ]
                )
            ),
        ]
        let findings = HardeningAssessment.assess(events: synthetic)
        XCTAssertTrue(findings.contains { $0.control == "notification_sensitive_marker" })
        for f in findings {
            XCTAssertFalse(f.detail.lowercased().contains("-----begin"))
            XCTAssertFalse(f.evidence.lowercased().contains("private key material dump"))
        }
    }
}
