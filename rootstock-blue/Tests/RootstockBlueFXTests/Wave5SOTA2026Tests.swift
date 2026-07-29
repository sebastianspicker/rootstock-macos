import XCTest
@testable import RootstockBlueFX
@testable import RootstockBlueCore
@testable import RootstockBlueCase
@testable import RootstockBlueDetect

/// Wave-5 2026 coverage expansion beyond shipped §7.1–§7.10:
/// AUTHPLUGINS, NETUSAGE, USBHISTORY, KEYCHAINMETA, CODESIGN, ARD
/// + harden controls with remediation (no secret export).
final class Wave5SOTA2026Tests: XCTestCase {
    var relativeRoot: URL {
        URL(fileURLWithPath: "Fixtures/artifacts/macos_sample")
    }

    var absoluteRoot: URL {
        relativeRoot.standardizedFileURL.resolvingSymlinksInPath()
    }

    private let wave5IDs = [
        "AUTHPLUGINS", "NETUSAGE", "USBHISTORY", "KEYCHAINMETA", "CODESIGN", "ARD",
    ]

    // MARK: - Runtime registration

    func testPluginRuntimeIncludesWave5Parsers() {
        let ids = Set(PluginRuntime().parserIDs())
        for id in wave5IDs {
            XCTAssertTrue(ids.contains(id), "defaultTier1 missing wave-5 parser \(id)")
        }
        // Regression: Wave-4 still present
        for id in ["PRIVHELPERS", "FOLDERACTIONS", "LOGINHOOKS"] {
            XCTAssertTrue(ids.contains(id), "regression: missing wave-4 family \(id)")
        }
        // Regression: Wave-3 still present
        for id in ["SHELLPROFILES", "EMOND", "SUDOERS", "LAUNCHDOVERRIDES"] {
            XCTAssertTrue(ids.contains(id), "regression: missing wave-3 family \(id)")
        }
    }

    // MARK: - AUTHPLUGINS

    func testAuthPluginsParserEmitsUnknownPlugin() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try AuthPluginsParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "expected authorization plugin events")
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "AUTHPLUGINS" })
        XCTAssertTrue(events.allSatisfy { $0.eventType == "persistence.item" })
        XCTAssertTrue(events.contains { $0.fields["persistence.kind"] == "authorization_plugin" })

        let names = events.compactMap { $0.fields["auth.plugin_name"] ?? $0.fields["persistence.label"] }.joined(separator: " ")
        XCTAssertTrue(names.lowercased().contains("evil") || names.contains("authplugin"), "names=\(names)")

        let risk = events.compactMap { $0.fields["persistence.risk_tags"] }.joined(separator: ",")
        XCTAssertTrue(
            risk.contains("unknown_vendor") || risk.contains("unsigned") || names.lowercased().contains("evil"),
            "expected risk tags, got risk=\(risk) names=\(names)"
        )
        XCTAssertTrue(events.contains { !$0.entityRefs.isEmpty })
    }

    // MARK: - NETUSAGE

    func testNetUsageParserEmitsAnomalousEgress() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try NetUsageParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "expected net usage events")
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "NETUSAGE" })
        XCTAssertTrue(events.contains { $0.eventType == "network.usage" })

        let risk = events.compactMap { $0.fields["net.risk_tags"] }.joined(separator: ",")
        let domains = events.compactMap { $0.fields["net.usage.domain"] }.joined(separator: " ")
        XCTAssertTrue(
            risk.contains("anomalous_egress") || risk.contains("high_volume")
                || risk.contains("suspicious_process") || domains.contains("evil"),
            "expected anomalous egress signal, risk=\(risk) domains=\(domains)"
        )
        XCTAssertTrue(events.contains {
            !($0.fields["net.usage.process"] ?? "").isEmpty
                || !($0.fields["net.usage.bytes_out"] ?? "").isEmpty
        })
    }

    // MARK: - USBHISTORY

    func testUSBHistoryParserEmitsDeviceEvents() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try USBHistoryParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "expected USB history events")
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "USBHISTORY" })
        XCTAssertTrue(events.contains { $0.eventType == "device.usb" })
        XCTAssertTrue(events.contains {
            !($0.fields["usb.product_name"] ?? $0.fields["usb.vendor_id"] ?? "").isEmpty
        })
    }

    // MARK: - KEYCHAINMETA

    func testKeychainMetaParserMetadataOnlyNoSecrets() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try KeychainMetaParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "expected keychain metadata events")
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "KEYCHAINMETA" })
        XCTAssertTrue(events.contains { $0.eventType == "keychain.metadata" })

        // Non-goal: never export secret material
        for e in events {
            let keys = e.fields.keys.map { $0.lowercased() }
            XCTAssertFalse(keys.contains("password"), "must not emit password field: \(e.fields)")
            XCTAssertFalse(keys.contains("secret"), "must not emit secret field: \(e.fields)")
            XCTAssertFalse(keys.contains("private_key"), "must not emit private_key: \(e.fields)")
            XCTAssertFalse(keys.contains { $0.contains("password") && !$0.contains("class") })
            let joined = e.fields.values.joined(separator: " ").lowercased()
            // Values should not look like dumped secrets (hex blobs / kcpassword)
            XCTAssertFalse(joined.contains("-----begin"), "must not dump PEM key material")
        }

        let risk = events.compactMap { $0.fields["keychain.risk_tags"] }.joined(separator: ",")
        XCTAssertTrue(
            risk.contains("suspicious") || risk.contains("unexpected") || risk.contains("evil")
                || events.contains { ($0.fields["keychain.label"] ?? "").lowercased().contains("evil") },
            "expected metadata anomaly tags, risk=\(risk)"
        )
    }

    // MARK: - CODESIGN

    func testCodesignParserEmitsUnsignedPersistence() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try CodesignParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "expected codesign assessment events")
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "CODESIGN" })
        XCTAssertTrue(events.contains { $0.eventType == "codesign.assessment" })

        let risk = events.compactMap { $0.fields["codesign.risk_tags"] }.joined(separator: ",")
        XCTAssertTrue(
            risk.contains("unsigned") || risk.contains("not_notarized") || risk.contains("adhoc")
                || events.contains { $0.fields["codesign.signed"] == "false" },
            "expected unsigned/not-notarized signal, risk=\(risk)"
        )
        XCTAssertTrue(events.contains { !($0.fields["codesign.path"] ?? "").isEmpty })
    }

    // MARK: - ARD

    func testARDParserEmitsAllLocalUsers() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try ARDParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "expected ARD events")
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "ARD" })
        XCTAssertTrue(events.contains {
            $0.eventType == "remote.management"
                || $0.eventType == "ir.posture.remote_access"
                || $0.fields["remote.service"] == "ard"
                || $0.fields["ard.enabled"] == "true"
        })
        XCTAssertTrue(
            events.contains {
                $0.fields["ard.all_local_users"] == "true"
                    || ($0.fields["ard.users"] ?? "").lowercased().contains("all")
            },
            "expected ARD_AllLocalUsers signal"
        )
    }

    // MARK: - Engine + parity

    func testForensicsEngineEmitsWave5Plugins() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try ForensicsEngine().parse(source: .directory(relativeRoot))
        let plugins = Set(events.map(\.sourcePlugin))
        for id in wave5IDs {
            XCTAssertTrue(plugins.contains(id), "engine missing events from \(id); have \(plugins.sorted())")
        }
    }

    func testRelativeAbsoluteParityWave5() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let parsers: [any ArtifactParser] = [
            AuthPluginsParser(),
            NetUsageParser(),
            USBHistoryParser(),
            KeychainMetaParser(),
            CodesignParser(),
            ARDParser(),
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

    // MARK: - Hardening assessment Wave-5

    func testHardeningAssessmentWave5ControlsWithRemediation() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let findings = try HardeningAssessment.assessOffline(source: .directory(relativeRoot))
        XCTAssertFalse(findings.isEmpty)

        let controls = Set(findings.map(\.control))
        XCTAssertTrue(controls.contains("auth_plugin_unknown"), "controls=\(controls)")
        XCTAssertTrue(controls.contains("netusage_anomalous_egress"), "controls=\(controls)")
        XCTAssertTrue(controls.contains("unsigned_persistence_binary"), "controls=\(controls)")
        XCTAssertTrue(controls.contains("keychain_metadata_anomaly"), "controls=\(controls)")
        XCTAssertTrue(controls.contains("ard_all_local_users"), "controls=\(controls)")

        let fails = findings.filter { $0.status == "fail" || $0.status == "warn" }
        XCTAssertFalse(fails.isEmpty)
        for f in fails where [
            "auth_plugin_unknown", "netusage_anomalous_egress",
            "unsigned_persistence_binary", "keychain_metadata_anomaly", "ard_all_local_users",
        ].contains(f.control) {
            XCTAssertFalse(f.remediation.isEmpty, "empty remediation for \(f.control)")
        }

        // Regression: Wave-4 still assessed
        XCTAssertTrue(
            controls.contains("login_hook_present")
                || controls.contains("privileged_helper_unknown")
                || controls.contains("remote_login")
        )
    }

    func testHardeningWave5PureFromSyntheticEvents() {
        let synthetic = [
            HardeningTestFixtures.event("AUTHPLUGINS", "persistence.item", ["persistence.kind": "authorization_plugin", "auth.plugin_name": "com.evil.authplugin", "persistence.risk_tags": "unknown_vendor,unsigned"]),
            HardeningTestFixtures.event("NETUSAGE", "network.usage", ["net.usage.process": "evil-agent", "net.usage.bytes_out": "999999999", "net.usage.domain": "c2.evil.example", "net.risk_tags": "anomalous_egress,high_volume"]),
            HardeningTestFixtures.event("CODESIGN", "codesign.assessment", ["codesign.path": "/Library/PrivilegedHelperTools/com.evil.privhelper", "codesign.signed": "false", "codesign.notarized": "false", "codesign.risk_tags": "unsigned,not_notarized"]),
            HardeningTestFixtures.event("KEYCHAINMETA", "keychain.metadata", ["keychain.label": "evil-implant-token", "keychain.access_group": "com.evil.implant", "keychain.risk_tags": "suspicious_label,unexpected_access_group"]),
            HardeningTestFixtures.event("ARD", "remote.management", ["ard.enabled": "true", "ard.all_local_users": "true", "remote.service": "ard", "remote.enabled": "true"]),
        ]
        let findings = HardeningAssessment.assess(events: synthetic)
        let controls = ["auth_plugin_unknown", "netusage_anomalous_egress", "unsigned_persistence_binary", "keychain_metadata_anomaly", "ard_all_local_users"]
        for control in controls {
            XCTAssertTrue(findings.contains { $0.control == control && $0.status == "fail" })
            XCTAssertFalse(findings.first { $0.control == control }!.remediation.isEmpty, control)
        }
    }

    func testHardeningWriteToCaseWave5() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("wave5-harden-\(UUID().uuidString).rsbcase")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let pkg = try CasePackage.create(at: tmp, name: "wave5-harden")
        let findings = try HardeningAssessment.assessOffline(source: .directory(relativeRoot))
        let n = try HardeningAssessment.writeToCase(findings, package: pkg, mode: "offline")
        XCTAssertGreaterThan(n, 0)
        let events = try pkg.loadAllEvents()
        XCTAssertTrue(events.contains {
            $0.sourcePlugin == "HARDEN"
                && (
                    $0.fields["harden.control"] == "auth_plugin_unknown"
                        || $0.fields["harden.control"] == "unsigned_persistence_binary"
                        || $0.fields["harden.control"] == "ard_all_local_users"
                        || $0.fields["harden.control"] == "netusage_anomalous_egress"
                        || $0.fields["harden.control"] == "keychain_metadata_anomaly"
                )
        })
        let custody = try String(contentsOf: pkg.custodyURL, encoding: .utf8)
        XCTAssertTrue(custody.contains("harden_assess"), custody)
    }

    // MARK: - Inventory merge

    func testPersistenceInventoryIncludesAuthPlugins() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let inv = try PersistenceInventory.enumerate(source: .directory(relativeRoot))
        XCTAssertFalse(inv.isEmpty)
        let sources = Set(inv.compactMap { $0.fields["inventory.source"] })
        XCTAssertTrue(
            sources.contains("authorization_plugin") || sources.contains("auth_plugin"),
            "inventory sources: \(sources)"
        )
        // Prior wave sources still present
        XCTAssertTrue(
            sources.contains("privileged_helper")
                || sources.contains("folder_action")
                || sources.contains("login_hook")
        )
    }

    // MARK: - Full shipped path

    func testParseIntoCaseDetectsWave5Signals() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("wave5-case-\(UUID().uuidString).rsbcase")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let pkg = try CasePackage.create(at: tmp, name: "wave5")
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
        for id in wave5IDs {
            XCTAssertTrue(plugins.contains(id), "timeline missing \(id)")
        }
        XCTAssertTrue(plugins.contains("HARDEN"))

        let rulesDir = URL(fileURLWithPath: "Content/detections/samples")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: rulesDir.path))
        let findings = try DetectionEngine().evaluate(rulesDirectory: rulesDir, events: timeline)
        let ids = Set(findings.map(\.ruleID))
        let wave5Hits = ids.filter {
            $0.contains("auth_plugin") || $0.contains("netusage") || $0.contains("unsigned_persistence")
                || $0.contains("keychain_metadata") || $0.contains("ard_all")
                || $0.contains("codesign")
        }
        XCTAssertFalse(
            wave5Hits.isEmpty,
            "expected wave-5 detection hits from real timeline, got rule ids: \(ids.sorted())"
        )
    }

    func testWave5DetectionFixturesViaFixtureRunner() throws {
        let rulesDir = URL(fileURLWithPath: "Content/detections/samples")
        let fixturesDir = rulesDir.appendingPathComponent("fixtures")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: rulesDir.path))

        let wave5Rules = [
            "auth_plugin_unknown.yaml",
            "netusage_anomalous_egress.yaml",
            "unsigned_persistence_codesign.yaml",
            "keychain_metadata_anomaly.yaml",
            "ard_all_local_users.yaml",
        ]
        for name in wave5Rules {
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

    func testNonGoalKeychainNoSecretExportInAssess() {
        let synthetic: [EventEnvelope] = [
            EventEnvelope(
                identity: EventEnvelope.Identity(
                    kind: "keychain.metadata",
                    label: "KEYCHAINMETA"
                ),
                capture: EventEnvelope.Capture(
                    source: .parser
                ),
                payload: EventEnvelope.Payload(
                    properties: [
                    "keychain.label": "com.evil.token",
                    "keychain.risk_tags": "suspicious_label",
                ]
                )
            ),
        ]
        let findings = HardeningAssessment.assess(events: synthetic)
        let kc = findings.filter { $0.control == "keychain_metadata_anomaly" }
        XCTAssertFalse(kc.isEmpty)
        for f in kc {
            XCTAssertFalse(f.remediation.lowercased().contains("export password"))
            XCTAssertFalse(f.detail.lowercased().contains("-----begin"))
            XCTAssertTrue(
                f.remediation.lowercased().contains("metadata")
                    || f.remediation.lowercased().contains("keychain")
                    || f.remediation.lowercased().contains("review")
            )
        }
    }
}
