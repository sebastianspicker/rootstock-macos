import XCTest
@testable import RootstockBlueFX
@testable import RootstockBlueCore
@testable import RootstockBlueCase
@testable import RootstockBlueDetect

/// Wave-7 2026 coverage expansion beyond shipped §7.1–§7.12:
/// COOKIES, BOOKMARKS, OFFICEMRU, PRINTJOBS, NOTES, IDEVICEBACKUP, MSRDC, CLOUDSYNC
/// + harden controls with remediation.
final class Wave7SOTA2026Tests: XCTestCase {
    var relativeRoot: URL {
        URL(fileURLWithPath: "Fixtures/artifacts/macos_sample")
    }

    var absoluteRoot: URL {
        relativeRoot.standardizedFileURL.resolvingSymlinksInPath()
    }

    private let wave7IDs = [
        "COOKIES", "BOOKMARKS", "OFFICEMRU", "PRINTJOBS",
        "NOTES", "IDEVICEBACKUP", "MSRDC", "CLOUDSYNC",
    ]

    private let wave7HardenControls = [
        "cookie_evil_domain",
        "bookmark_evil_domain",
        "office_mru_sensitive",
        "print_sensitive_job",
        "notes_sensitive_marker",
        "idevice_backup_unencrypted",
        "msrdc_remote_connection",
        "cloudsync_exfil_provider",
    ]

    // MARK: - Runtime registration

    func testPluginRuntimeIncludesWave7Parsers() {
        let ids = Set(PluginRuntime().parserIDs())
        for id in wave7IDs {
            XCTAssertTrue(ids.contains(id), "defaultTier1 missing wave-7 parser \(id)")
        }
        // Regression: Wave-6 still present
        for id in ["SPOTLIGHT", "TRASH", "FIREFOX", "ICLOUD", "NOTIFICATIONS"] {
            XCTAssertTrue(ids.contains(id), "regression: missing wave-6 family \(id)")
        }
        // Regression: Wave-5 still present
        for id in ["AUTHPLUGINS", "NETUSAGE", "USBHISTORY", "KEYCHAINMETA", "CODESIGN", "ARD"] {
            XCTAssertTrue(ids.contains(id), "regression: missing wave-5 family \(id)")
        }
    }

    // MARK: - Family parsers

    func testCookiesParserEmitsDomainRiskNoValues() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try CookiesParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "expected cookie events")
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "COOKIES" })
        XCTAssertTrue(events.contains { $0.eventType == "browser.cookie" })
        let risk = events.compactMap { $0.fields["cookie.risk_tags"] }.joined(separator: ",")
        let domains = events.compactMap { $0.fields["cookie.domain"] }.joined(separator: " ")
        XCTAssertTrue(
            risk.contains("evil_domain") || domains.contains("evil"),
            "risk=\(risk) domains=\(domains)"
        )
        XCTAssertTrue(events.contains { $0.fields["cookie.value_exported"] == "false" })
        // Non-goal: never export raw cookie values
        for e in events {
            XCTAssertNil(e.fields["cookie.value"])
            XCTAssertNil(e.fields["value"])
            let joined = e.fields.values.joined(separator: " ")
            XCTAssertFalse(joined.contains("supersecrettoken"), "must not dump raw cookie value")
        }
        XCTAssertTrue(events.contains { !$0.entityRefs.isEmpty })
    }

    func testBookmarksParserEmitsEvilDomain() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try BookmarksParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty)
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "BOOKMARKS" })
        XCTAssertTrue(events.contains { $0.eventType == "browser.bookmark" })
        let risk = events.compactMap { $0.fields["bookmark.risk_tags"] }.joined(separator: ",")
        let urls = events.compactMap { $0.fields["bookmark.url"] }.joined(separator: " ")
        XCTAssertTrue(
            risk.contains("evil_domain") || urls.contains("evil") || risk.contains("script_bookmark"),
            "risk=\(risk) urls=\(urls)"
        )
    }

    func testOfficeMRUParserEmitsSensitiveDocs() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try OfficeMRUParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty)
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "OFFICEMRU" })
        XCTAssertTrue(events.contains { $0.eventType == "mru.office" })
        let risk = events.compactMap { $0.fields["office.risk_tags"] }.joined(separator: ",")
        XCTAssertTrue(
            risk.contains("sensitive") || risk.contains("tmp_path") || risk.contains("suspicious"),
            "risk=\(risk)"
        )
        XCTAssertTrue(events.contains { !($0.fields["office.app"] ?? "").isEmpty })
    }

    func testPrintJobsParserEmitsSensitiveJobs() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try PrintJobsParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty)
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "PRINTJOBS" })
        XCTAssertTrue(events.contains { $0.eventType == "print.job" })
        let risk = events.compactMap { $0.fields["print.risk_tags"] }.joined(separator: ",")
        let docs = events.compactMap { $0.fields["print.document"] }.joined(separator: " ")
        XCTAssertTrue(
            risk.contains("sensitive") || docs.contains("password") || docs.contains("evil"),
            "risk=\(risk) docs=\(docs)"
        )
    }

    func testNotesParserMetadataOnlyNoBody() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try NotesParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty)
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "NOTES" })
        XCTAssertTrue(events.contains { $0.eventType == "notes.metadata" })
        let risk = events.compactMap { $0.fields["notes.risk_tags"] }.joined(separator: ",")
        XCTAssertTrue(risk.contains("sensitive"), "risk=\(risk)")
        for e in events {
            XCTAssertEqual(e.fields["notes.body_exported"], "false")
            XCTAssertNil(e.fields["notes.body"])
            XCTAssertNil(e.fields["body"])
            XCTAssertNil(e.fields["content"])
        }
    }

    func testIDeviceBackupParserEmitsUnencrypted() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try IDeviceBackupParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty)
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "IDEVICEBACKUP" })
        XCTAssertTrue(events.contains { $0.eventType == "backup.idevice" })
        XCTAssertTrue(events.contains { $0.fields["backup.encrypted"] == "false" })
        XCTAssertTrue(events.contains { ($0.fields["backup.risk_tags"] ?? "").contains("unencrypted") })
    }

    func testMSRDCParserEmitsRemoteConnections() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try MSRDCParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty)
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "MSRDC" })
        XCTAssertTrue(events.contains { $0.eventType == "remote.rdp_connection" })
        let hosts = events.compactMap { $0.fields["rdp.host"] }.joined(separator: " ")
        let risk = events.compactMap { $0.fields["rdp.risk_tags"] }.joined(separator: ",")
        XCTAssertTrue(hosts.contains("evil") || risk.contains("remote_connection"), "hosts=\(hosts) risk=\(risk)")
        XCTAssertTrue(events.contains { !$0.entityRefs.isEmpty })
    }

    func testCloudSyncParserEmitsMultiProvider() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try CloudSyncParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty)
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "CLOUDSYNC" })
        XCTAssertTrue(events.contains { $0.eventType == "cloud.provider_sync" })
        let providers = Set(events.compactMap { $0.fields["cloud.provider"] })
        XCTAssertTrue(
            providers.contains("dropbox") || providers.contains("onedrive")
                || providers.contains("google_drive") || providers.contains("box"),
            "providers=\(providers)"
        )
        let risk = events.compactMap { $0.fields["cloud.risk_tags"] }.joined(separator: ",")
        XCTAssertTrue(risk.contains("exfil") || risk.contains("sync_enabled"), "risk=\(risk)")
        // Account markers must not dump full emails when @ present
        for e in events {
            if let acct = e.fields["cloud.account_marker"], acct.contains("@") {
                XCTAssertTrue(acct.hasPrefix("***@") || acct.contains("***"), "acct=\(acct)")
            }
        }
    }

    func testForensicsEngineEmitsWave7Plugins() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try ForensicsEngine().parse(source: .directory(relativeRoot))
        let plugins = Set(events.map(\.sourcePlugin))
        for id in wave7IDs {
            XCTAssertTrue(plugins.contains(id), "ForensicsEngine missing \(id); have \(plugins.sorted())")
        }
    }

    func testRelativeAbsoluteParityWave7() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let parsers: [any ArtifactParser] = [
            CookiesParser(), BookmarksParser(), OfficeMRUParser(), PrintJobsParser(),
            NotesParser(), IDeviceBackupParser(), MSRDCParser(), CloudSyncParser(),
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

    func testHardeningAssessmentWave7ControlsWithRemediation() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let findings = try HardeningAssessment.assessOffline(source: .directory(relativeRoot))
        XCTAssertFalse(findings.isEmpty)

        let controls = Set(findings.map(\.control))
        for control in wave7HardenControls {
            XCTAssertTrue(controls.contains(control), "missing control \(control); have \(controls.sorted())")
        }

        let fails = findings.filter {
            wave7HardenControls.contains($0.control) && ($0.status == "fail" || $0.status == "warn")
        }
        XCTAssertFalse(fails.isEmpty)
        for f in fails {
            XCTAssertFalse(f.remediation.isEmpty, "empty remediation for \(f.control)")
        }

        // Regression: Wave-6 still assessed
        XCTAssertTrue(
            controls.contains("trash_sensitive_artifact")
                || controls.contains("icloud_desktop_documents_sync")
                || controls.contains("firefox_suspicious_download")
        )
    }

    func testHardeningWave7PureFromSyntheticEvents() {
        let synthetic = [
            HardeningTestFixtures.event("COOKIES", "browser.cookie", ["cookie.domain": "evil.example", "cookie.name_marker": "sessionid", "cookie.value_exported": "false", "cookie.risk_tags": "evil_domain,session_cookie"]),
            HardeningTestFixtures.event("BOOKMARKS", "browser.bookmark", ["bookmark.url": "https://evil.example/panel", "bookmark.title": "Evil", "bookmark.risk_tags": "evil_domain"]),
            HardeningTestFixtures.event("OFFICEMRU", "mru.office", ["office.app": "Word", "office.path": "/tmp/evil-passwords.docx", "office.risk_tags": "sensitive_document,tmp_path"]),
            HardeningTestFixtures.event("PRINTJOBS", "print.job", ["print.document": "employee_passwords.pdf", "print.risk_tags": "sensitive_document"]),
            HardeningTestFixtures.event("NOTES", "notes.metadata", ["notes.title_marker": "WiFi password office", "notes.body_exported": "false", "notes.risk_tags": "sensitive_title"]),
            HardeningTestFixtures.event("IDEVICEBACKUP", "backup.idevice", ["backup.device_name": "Alice iPhone", "backup.encrypted": "false", "backup.risk_tags": "unencrypted_backup"]),
            HardeningTestFixtures.event("MSRDC", "remote.rdp_connection", ["rdp.host": "evil.example", "rdp.user": "admin", "rdp.risk_tags": "remote_connection,suspicious_host"]),
            HardeningTestFixtures.event("CLOUDSYNC", "cloud.provider_sync", ["cloud.provider": "dropbox", "cloud.sync_enabled": "true", "cloud.risk_tags": "sync_enabled,exfil_capable_provider"]),
        ]
        let findings = HardeningAssessment.assess(events: synthetic)
        for control in wave7HardenControls {
            XCTAssertTrue(findings.contains { $0.control == control && $0.status == "fail" }, "expected fail for \(control); have \(findings.map(\.control))")
            XCTAssertFalse(findings.first { $0.control == control }!.remediation.isEmpty, control)
        }
    }

    func testHardeningWriteToCaseWave7() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("wave7-harden-\(UUID().uuidString).rsbcase")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let pkg = try CasePackage.create(at: tmp, name: "wave7-harden")
        let findings = try HardeningAssessment.assessOffline(source: .directory(relativeRoot))
        let n = try HardeningAssessment.writeToCase(findings, package: pkg, mode: "offline")
        XCTAssertGreaterThan(n, 0)
        let events = try pkg.loadAllEvents()
        XCTAssertTrue(events.contains {
            $0.sourcePlugin == "HARDEN" && wave7HardenControls.contains($0.fields["harden.control"] ?? "")
        })
        let custody = try String(contentsOf: pkg.custodyURL, encoding: .utf8)
        XCTAssertTrue(custody.contains("harden_assess"), custody)
    }

    // MARK: - Full shipped path

    func testParseIntoCaseDetectsWave7Signals() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("wave7-case-\(UUID().uuidString).rsbcase")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let pkg = try CasePackage.create(at: tmp, name: "wave7")
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
        for id in wave7IDs { XCTAssertTrue(plugins.contains(id), "timeline missing \(id)") }
        XCTAssertTrue(plugins.contains("HARDEN"))
        let rulesDir = URL(fileURLWithPath: "Content/detections/samples")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: rulesDir.path))
        let ids = Set(try DetectionEngine().evaluate(rulesDirectory: rulesDir, events: timeline).map(\.ruleID))
        let fragments = ["cookie", "bookmark", "office_mru", "print", "notes", "idevice", "msrdc", "cloudsync"]
        XCTAssertTrue(ids.contains { id in fragments.contains { id.contains($0) } }, "expected wave-7 detection hits from real timeline, got rule ids: \(ids.sorted())")
    }

    func testWave7DetectionFixturesViaFixtureRunner() throws {
        let rulesDir = URL(fileURLWithPath: "Content/detections/samples")
        let fixturesDir = rulesDir.appendingPathComponent("fixtures")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: rulesDir.path))

        let wave7Rules = [
            "cookie_evil_domain.yaml",
            "bookmark_evil_domain.yaml",
            "office_mru_sensitive.yaml",
            "print_sensitive_job.yaml",
            "notes_sensitive_marker.yaml",
            "idevice_backup_unencrypted.yaml",
            "msrdc_remote_connection.yaml",
            "cloudsync_exfil_provider.yaml",
        ]
        for name in wave7Rules {
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

    func testNonGoalCookiesNoValueExportAndNotesNoBody() {
        let findings = HardeningAssessment.assess(events: nonGoalSafetyEvents())
        XCTAssertTrue(findings.contains { $0.control == "cookie_evil_domain" })
        XCTAssertTrue(findings.contains { $0.control == "notes_sensitive_marker" })
        assertNonGoalSafety(findings)
    }

    private func nonGoalSafetyEvents() -> [EventEnvelope] {
        [nonGoalCookieEvent(), nonGoalNotesEvent()]
    }

    private func nonGoalCookieEvent() -> EventEnvelope {
        EventEnvelope(identity: .init(kind: "browser.cookie", label: "COOKIES"), capture: .init(source: .parser), payload: .init(properties: ["cookie.domain": "evil.example", "cookie.name_marker": "sessionid", "cookie.value_exported": "false", "cookie.risk_tags": "evil_domain"]))
    }

    private func nonGoalNotesEvent() -> EventEnvelope {
        EventEnvelope(identity: .init(kind: "notes.metadata", label: "NOTES"), capture: .init(source: .parser), payload: .init(properties: ["notes.title_marker": "password dump", "notes.body_exported": "false", "notes.risk_tags": "sensitive_title"]))
    }

    private func assertNonGoalSafety(_ findings: [HardeningAssessment.Finding]) {
        for f in findings {
            XCTAssertFalse(f.detail.lowercased().contains("-----begin"))
            XCTAssertFalse(f.remediation.lowercased().contains("export raw session cookie values into siem")
                && f.control == "cookie_evil_domain" && f.remediation.contains("Do not") == false)
            // Remediation for cookies should warn against value export
            if f.control == "cookie_evil_domain" {
                XCTAssertTrue(f.remediation.lowercased().contains("do not export raw")
                    || f.remediation.lowercased().contains("not export"))
            }
            if f.control == "notes_sensitive_marker" {
                XCTAssertTrue(f.detail.lowercased().contains("not exported")
                    || f.remediation.lowercased().contains("do not dump"))
            }
        }
    }
}
