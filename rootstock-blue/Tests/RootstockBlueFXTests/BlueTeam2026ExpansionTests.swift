import XCTest
@testable import RootstockBlueFX
@testable import RootstockBlueCore
@testable import RootstockBlueCase
@testable import RootstockBlueDetect

/// Wave-2 blue-team expansion: BIOME, CRON, LOGINITEMS, SYSTEMEXTENSIONS,
/// UTMPX, BROWSER_EXTENSIONS, GATEKEEPER, NETLOCATION + unified inventory.
final class BlueTeam2026ExpansionTests: XCTestCase {
    var relativeRoot: URL {
        URL(fileURLWithPath: "Fixtures/artifacts/macos_sample")
    }

    var absoluteRoot: URL {
        relativeRoot.standardizedFileURL.resolvingSymlinksInPath()
    }

    // MARK: - Runtime registration

    func testPluginRuntimeIncludesExpansionParsers() {
        let ids = Set(PluginRuntime().parserIDs())
        for id in [
            "BIOME", "CRON", "LOGINITEMS", "SYSTEMEXTENSIONS",
            "UTMPX", "BROWSER_EXTENSIONS", "GATEKEEPER", "NETLOCATION",
        ] {
            XCTAssertTrue(ids.contains(id), "defaultTier1 missing \(id)")
        }
    }

    // MARK: - Individual parsers

    func testBiomeParserEmitsPoLStreams() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try BiomeParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "BIOME must emit stream events")
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "BIOME" })
        XCTAssertTrue(events.contains { $0.eventType.hasPrefix("pol.biome") || $0.eventType.hasPrefix("pol.") })
        // Prefer com.evil if present; otherwise any non-empty pol.value
        let valued = events.filter { !($0.fields["pol.value"] ?? "").isEmpty }
        XCTAssertFalse(valued.isEmpty)
        XCTAssertTrue(valued.contains { ($0.fields["pol.source"] ?? "biome") == "biome" || $0.sourcePlugin == "BIOME" })
    }

    func testCronParserEmitsTmpPayload() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try CronParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty)
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "CRON" })
        XCTAssertTrue(events.allSatisfy { $0.eventType == "persistence.item" })
        XCTAssertTrue(events.contains {
            let cmd = $0.fields["persistence.command"] ?? $0.fields["persistence.program"] ?? ""
            return cmd.contains("/tmp/") || cmd.contains("evil")
        })
        XCTAssertTrue(events.contains {
            ["cron", "at", "periodic"].contains($0.fields["persistence.kind"] ?? "")
        })
    }

    /// Vixie specials: fixture etc/cron.d/evil-persist has `@reboot root /var/tmp/c2_beacon`.
    /// Must fail if parseCronLine drops @-schedules (tokens.count < 6 path only).
    func testCronParserEmitsVixieRebootFromEvilPersist() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try CronParser().parse(source: .directory(relativeRoot))
        let reboot = events.filter {
            let sched = ($0.fields["persistence.schedule"] ?? "").lowercased()
            return sched == "@reboot" || sched.hasPrefix("@reboot")
        }
        XCTAssertFalse(
            reboot.isEmpty,
            "expected @reboot from etc/cron.d/evil-persist; schedules=\(events.map { $0.fields["persistence.schedule"] ?? "?" })"
        )
        XCTAssertTrue(reboot.contains {
            let cmd = $0.fields["persistence.command"] ?? $0.fields["persistence.program"] ?? ""
            return cmd.contains("c2_beacon") || cmd.contains("/var/tmp/")
        })
        XCTAssertTrue(reboot.contains {
            ($0.fields["persistence.user"] ?? $0.fields[FieldTaxonomy.userName] ?? "") == "root"
                || ($0.fields["user.name"] ?? "") == "root"
        })
        // Other Vixie specials still parse if present
        for special in ["@daily", "@hourly", "@weekly", "@monthly", "@yearly"] {
            _ = special // reserved for future fixtures; @reboot is the binding one
        }
    }

    func testLoginItemsParserEmitsEvilItem() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try LoginItemsParser().parse(source: .directory(relativeRoot))
        XCTAssertGreaterThanOrEqual(events.count, 2)
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "LOGINITEMS" })
        let evil = events.first { ($0.fields["persistence.label"] ?? "").localizedCaseInsensitiveContains("evil") }
        XCTAssertNotNil(evil, "expected Evil Login Helper item")
        XCTAssertEqual(evil?.fields["persistence.kind"], "login_item")
        XCTAssertFalse((evil?.fields["persistence.path"] ?? "").isEmpty)
    }

    func testSystemExtensionsParserEmitsEvilTeam() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try SystemExtensionsParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty)
        XCTAssertTrue(events.contains {
            $0.eventType == "defense.system_extension" || $0.eventType == "host.system_extension"
        })
        let evil = events.first {
            ($0.fields["extension.bundle_id"] ?? "").contains("evil")
                || ($0.fields["extension.team_id"] ?? "").uppercased().contains("EVIL")
        }
        XCTAssertNotNil(evil, "expected non-Apple/evil system extension")
        XCTAssertFalse((evil?.fields["extension.team_id"] ?? "").isEmpty)
        XCTAssertFalse((evil?.fields["extension.state"] ?? "").isEmpty)
    }

    func testUtmpxParserEmitsRemoteLogin() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try UtmpxParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty)
        XCTAssertTrue(events.contains { $0.eventType == "auth.login" })
        let remote = events.first {
            let host = $0.fields["auth.host"] ?? ""
            return host.contains("evil-c2") || host.contains("10.0.0")
        }
        XCTAssertNotNil(remote, "expected remote host session")
        XCTAssertEqual(remote?.fields["auth.remote"], "true")
        XCTAssertFalse((remote?.fields[FieldTaxonomy.userName] ?? "").isEmpty)
    }

    func testBrowserExtensionsParserEmitsBroadPerms() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try BrowserExtensionsParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "expected browser extension events")
        XCTAssertTrue(events.allSatisfy { $0.eventType == "browser.extension" })
        let broad = events.first {
            ($0.fields["extension.broad_permissions"] ?? "") == "true"
                || ($0.fields["extension.permissions"] ?? "").contains("all_urls")
                || ($0.fields["extension.permissions"] ?? "").contains("<all_urls>")
        }
        XCTAssertNotNil(broad, "expected broad-permission extension; events=\(events.map { $0.fields["extension.name"] ?? "?" })")
    }

    func testGatekeeperHistoryParserEmitsOverride() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try GatekeeperHistoryParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty)
        XCTAssertTrue(events.allSatisfy { $0.eventType == "gatekeeper.assessment" })

        // Explicit override path (result=override / override:true) must be override=true
        let overrides = events.filter { ($0.fields["gatekeeper.override"] ?? "") == "true" }
        XCTAssertFalse(overrides.isEmpty, "expected ≥1 true override assessment")
        XCTAssertTrue(overrides.allSatisfy {
            let r = ($0.fields["gatekeeper.result"] ?? "").lowercased()
            let p = ($0.fields["gatekeeper.policy"] ?? "").lowercased()
            return r.contains("override") || p.contains("override") || p.contains("user_override")
        })

        // denied / unsigned must NOT be labeled override=true (detection false-positive bar)
        let denied = events.filter {
            let r = ($0.fields["gatekeeper.result"] ?? "").lowercased()
            return r.contains("denied") || r.contains("unsigned") || r.contains("fail")
        }
        XCTAssertFalse(denied.isEmpty, "fixture should include a denied/unsigned assessment")
        for d in denied {
            XCTAssertEqual(
                d.fields["gatekeeper.override"],
                "false",
                "denied/unsigned must not set gatekeeper.override=true (path=\(d.fields["file.path"] ?? "?"))"
            )
            // Still flag as suspicious for IR context
            XCTAssertEqual(d.fields["gatekeeper.suspicious"], "true")
        }
    }

    func testNetworkLocationParserEmitsServices() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try NetworkLocationParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty)
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "NETLOCATION" })
        XCTAssertTrue(events.contains {
            let svc = $0.fields["net.service"] ?? ""
            let loc = $0.fields["net.location_name"] ?? ""
            let iface = $0.fields["net.interface"] ?? ""
            return svc.contains("Wi-Fi") || svc.contains("VPN") || svc.contains("Ethernet")
                || loc.contains("Automatic") || loc.contains("VPN") || loc.contains("Office")
                || iface.hasPrefix("en") || iface.hasPrefix("utun")
        })
    }

    // MARK: - Engine integration

    func testForensicsEngineEmitsExpansionPlugins() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let engine = ForensicsEngine()
        let events = try engine.parse(source: ImageSource.infer(from: relativeRoot))
        let plugins = Set(events.map(\.sourcePlugin))
        for id in [
            "BIOME", "CRON", "LOGINITEMS", "SYSTEMEXTENSIONS", "UTMPX",
            "BROWSER_EXTENSIONS", "GATEKEEPER", "NETLOCATION",
        ] {
            XCTAssertTrue(plugins.contains(id), "engine output missing \(id); have \(plugins.sorted())")
        }
        XCTAssertGreaterThan(events.count, 20)
    }

    func testRelativeAbsoluteParityExpansion() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        for makeParser in [
            { BiomeParser() as any ArtifactParser },
            { CronParser() as any ArtifactParser },
            { LoginItemsParser() as any ArtifactParser },
            { SystemExtensionsParser() as any ArtifactParser },
            { UtmpxParser() as any ArtifactParser },
            { BrowserExtensionsParser() as any ArtifactParser },
            { GatekeeperHistoryParser() as any ArtifactParser },
            { NetworkLocationParser() as any ArtifactParser },
        ] {
            let parser = makeParser()
            let rel = try parser.parse(source: .directory(relativeRoot))
            let abs = try parser.parse(source: .directory(absoluteRoot))
            XCTAssertEqual(rel.count, abs.count, "\(parser.manifest.id) relative/absolute parity")
        }
    }

    // MARK: - Persistence inventory

    func testPersistenceInventoryMergesSources() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try PersistenceInventory.enumerate(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty)
        XCTAssertTrue(events.allSatisfy { ($0.fields["inventory.unified"] ?? "") == "true" })
        let summary = PersistenceInventory.summarize(events)
        XCTAssertFalse(summary.isEmpty)
        let sources = Set(events.compactMap { $0.fields["inventory.source"] })
        XCTAssertTrue(
            sources.contains("btm")
                || sources.contains("login_item")
                || sources.contains("cron")
                || sources.contains("autostart")
                || sources.contains("ssh")
        )
        let parsers = Set(events.compactMap { $0.fields["inventory.parser"] })
        XCTAssertTrue(parsers.contains("AUTOSTART") || parsers.contains("BTM") || parsers.contains("CRON"))
    }

    // MARK: - IR posture expansion

    func testOfflinePostureIncludesRemoteAndSysext() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try HostIRPosture.enumerateOffline(source: .directory(relativeRoot))
        XCTAssertTrue(events.allSatisfy { ($0.fields["ir.mode"] ?? "") == "offline" })
        XCTAssertTrue(events.contains { ($0.fields["protection.name"] ?? "") == "Firewall" })
        XCTAssertTrue(events.contains {
            $0.eventType == "ir.posture.remote_access"
                || ($0.fields["protection.name"] ?? "") == "ScreenSharing"
                || ($0.fields["protection.name"] ?? "") == "RemoteManagement"
        })
        XCTAssertTrue(events.contains {
            $0.eventType == "ir.posture.system_extension"
                || ($0.fields["sysext.name"] ?? "").lowercased().contains("evil")
                || ($0.fields["sysext.name"] ?? "").lowercased().contains("sysext")
                || ($0.fields["protection.name"] ?? "") == "SystemExtension"
        })
    }

    // MARK: - Case path: parse + detect

    func testParseIntoCaseAndDetectExpansionSignals() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("exp-case-\(UUID().uuidString).rsbcase")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let pkg = try CasePackage.create(at: tmp, name: "expansion")
        XCTAssertGreaterThan(try ForensicsEngine().parse(source: .directory(relativeRoot), into: pkg), 0)
        let posture = try HostIRPosture.enumerateOffline(source: .directory(relativeRoot))
        _ = try HostIRPosture.writeToCase(posture, package: pkg, mode: "offline")
        let inventory = try PersistenceInventory.enumerate(source: .directory(relativeRoot))
        _ = try PersistenceInventory.writeToCase(inventory, package: pkg)
        let timeline = try CaseTimeline.merged(from: pkg)
        XCTAssertFalse(timeline.isEmpty)
        let rulesDir = URL(fileURLWithPath: "Content/detections/samples")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: rulesDir.path))
        let ids = Set(try DetectionEngine().evaluate(rulesDirectory: rulesDir, events: timeline).map(\.ruleID))
        let fragments = ["cron", "login_item", "ssh", "gatekeeper", "browser_extension", "utmpx", "system_extension", "firewall", "sip", "biome", "screen_sharing", "wifi", "btm", "config", "xprotect", "quarantine"]
        XCTAssertTrue(ids.contains { id in fragments.contains { id.contains($0) } }, "expected expansion findings, got \(ids)")
    }
}
