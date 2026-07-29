import XCTest
@testable import RootstockBlueFX
@testable import RootstockBlueCore

/// 2026 coverage artifact families (BTM, WIFI, CONFIGPROFILES, SSH) - shipped parse path only.
final class SOTA2026FamiliesTests: XCTestCase {
    var relativeRoot: URL {
        URL(fileURLWithPath: "Fixtures/artifacts/macos_sample")
    }

    var absoluteRoot: URL {
        relativeRoot.standardizedFileURL.resolvingSymlinksInPath()
    }

    // MARK: - BTM

    func testBTMParserEmitsPersistenceItems() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try BTMParser().parse(source: .directory(relativeRoot))
        XCTAssertGreaterThanOrEqual(events.count, 2, "BTM must emit evil + Safari items")
        XCTAssertTrue(events.allSatisfy { $0.eventType == "persistence.btm_item" })
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "BTM" })
        XCTAssertTrue(events.allSatisfy { !$0.entityRefs.isEmpty })

        let evil = events.first { ($0.fields["btm.name"] ?? "") == "Evil Agent" }
        XCTAssertNotNil(evil, "expected Evil Agent BTM item")
        XCTAssertEqual(evil?.fields["btm.executable_path"], "/tmp/evil_payload")
        XCTAssertEqual(evil?.fields["btm.type"], "8")
        XCTAssertTrue((evil?.fields["btm.type_label"] ?? "").contains("agent"))
        XCTAssertEqual(evil?.fields["btm.user"], "alice")
        XCTAssertEqual(evil?.fields[FieldTaxonomy.userName], "alice")
        XCTAssertTrue(evil?.entityRefs.contains { $0.kind == .persistence } == true)
        XCTAssertTrue(evil?.entityRefs.contains { $0.kind == .file } == true)
        XCTAssertTrue(evil?.entityRefs.contains { $0.kind == .user } == true)

        let safari = events.first { ($0.fields["btm.name"] ?? "") == "Safari" }
        XCTAssertNotNil(safari)
        XCTAssertTrue((safari?.fields["btm.developer"] ?? "").contains("Apple"))
    }

    // MARK: - WIFI

    func testWifiParserEmitsPreferredNetworks() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try WifiParser().parse(source: .directory(relativeRoot))
        XCTAssertGreaterThanOrEqual(events.count, 2, "expected EvilCorp-Guest + HomeNet")
        XCTAssertTrue(events.allSatisfy { $0.eventType == "network.wifi_preferred" })
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "WIFI" })
        XCTAssertTrue(events.allSatisfy { !$0.entityRefs.isEmpty })
        XCTAssertTrue(events.allSatisfy { $0.entityRefs.contains { $0.kind == .network } })

        let guest = events.first { ($0.fields["wifi.ssid"] ?? "") == "EvilCorp-Guest" }
        XCTAssertNotNil(guest)
        XCTAssertEqual(guest?.fields["wifi.security"], "Open")
        XCTAssertEqual(guest?.fields["network.ssid"], "EvilCorp-Guest")
        XCTAssertEqual(guest?.entityRefs.first { $0.kind == .network }?.value, "ssid=EvilCorp-Guest")

        let home = events.first { ($0.fields["wifi.ssid"] ?? "") == "HomeNet" }
        XCTAssertNotNil(home)
        XCTAssertEqual(home?.fields["wifi.security"], "WPA2")
    }

    // MARK: - CONFIGPROFILES

    func testConfigProfilesParserEmitsMDMPayload() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try ConfigProfilesParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "CONFIGPROFILES must emit ≥1 profile")
        XCTAssertTrue(events.allSatisfy { $0.eventType == "host.config_profile" })
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "CONFIGPROFILES" })
        XCTAssertTrue(events.allSatisfy { !$0.entityRefs.isEmpty })

        let evil = events.first {
            ($0.fields["profile.identifier"] ?? "") == "com.evil.mdm.shell"
                || ($0.fields["profile.display_name"] ?? "").contains("Evil MDM Shell")
        }
        XCTAssertNotNil(evil, "expected Evil MDM Shell profile")
        XCTAssertEqual(evil?.fields["profile.display_name"], "Evil MDM Shell")
        XCTAssertEqual(evil?.fields["profile.identifier"], "com.evil.mdm.shell")
        XCTAssertEqual(evil?.fields["profile.type"], "com.apple.shell")
        XCTAssertEqual(evil?.fields["profile.organization"], "EvilCorp")
        XCTAssertTrue(evil?.entityRefs.contains { $0.kind == .host } == true)
        XCTAssertTrue(evil?.entityRefs.contains { $0.kind == .file } == true)
    }

    // MARK: - SSH

    func testSSHArtifactsParserEmitsKeysHostsAndConfig() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try SSHArtifactsParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty)
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "SSH" })
        XCTAssertTrue(events.allSatisfy { !$0.entityRefs.isEmpty })

        let authKeys = events.filter { $0.eventType == "auth.ssh_authorized_key" }
        XCTAssertFalse(authKeys.isEmpty, "expected authorized_keys event")
        XCTAssertTrue(authKeys.contains { ($0.fields["ssh.key_type"] ?? "") == "ssh-ed25519" })
        XCTAssertTrue(authKeys.contains { ($0.fields["ssh.key_comment"] ?? "") == "evil@c2" })
        XCTAssertTrue(authKeys.contains { ($0.fields["ssh.user"] ?? "") == "alice" })
        XCTAssertTrue(authKeys.contains { $0.entityRefs.contains { $0.kind == .auth } })
        XCTAssertTrue(authKeys.contains { $0.entityRefs.contains { $0.kind == .user } })

        let known = events.filter { $0.eventType == "auth.ssh_known_host" }
        XCTAssertFalse(known.isEmpty)
        XCTAssertTrue(known.contains {
            ($0.fields["ssh.host_pattern"] ?? "").contains("evil-c2.example.com")
        })
        XCTAssertTrue(known.contains { ($0.fields["ssh.key_type"] ?? "") == "ssh-ed25519" })

        let sshd = events.filter { $0.eventType == "auth.sshd_config" }
        XCTAssertFalse(sshd.isEmpty)
        XCTAssertTrue(sshd.contains {
            ($0.fields["ssh.directive"] ?? "") == "PermitRootLogin"
                && ($0.fields["ssh.value"] ?? "").lowercased() == "yes"
        })
        XCTAssertTrue(sshd.contains {
            ($0.fields["ssh.directive"] ?? "") == "PasswordAuthentication"
                && ($0.fields["ssh.value"] ?? "").lowercased() == "yes"
        })
    }

    // MARK: - Runtime / engine integration

    func testPluginRuntimeIncludesSOTA2026Parsers() {
        let ids = Set(PluginRuntime().parserIDs())
        for id in ["BTM", "WIFI", "CONFIGPROFILES", "SSH"] {
            XCTAssertTrue(ids.contains(id), "defaultTier1 missing \(id)")
        }
        let forensicsIDs = Set(PluginRuntime.defaultForensics().map(\.manifest.id))
        for id in ["BTM", "WIFI", "CONFIGPROFILES", "SSH"] {
            XCTAssertTrue(forensicsIDs.contains(id), "defaultForensics missing \(id)")
        }
    }

    func testForensicsEngineParseEmitsSOTA2026Plugins() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let engine = ForensicsEngine()
        let events = try engine.parse(source: ImageSource.infer(from: relativeRoot))
        let plugins = Set(events.map(\.sourcePlugin))
        for id in ["BTM", "WIFI", "CONFIGPROFILES", "SSH"] {
            XCTAssertTrue(plugins.contains(id), "engine output missing \(id)")
        }

        // Targeted plugin filter still works.
        let onlyBTM = try engine.parse(
            source: ImageSource.infer(from: relativeRoot),
            plugins: ["BTM"]
        )
        XCTAssertFalse(onlyBTM.isEmpty)
        XCTAssertTrue(onlyBTM.allSatisfy { $0.sourcePlugin == "BTM" })
    }

    func testRelativeAbsoluteParityForNewParsers() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))

        for makeParser in [
            { BTMParser() as any ArtifactParser },
            { WifiParser() as any ArtifactParser },
            { ConfigProfilesParser() as any ArtifactParser },
            { SSHArtifactsParser() as any ArtifactParser },
        ] {
            let parser = makeParser()
            let rel = try parser.parse(source: .directory(relativeRoot))
            let abs = try parser.parse(source: .directory(absoluteRoot))
            XCTAssertEqual(
                rel.count,
                abs.count,
                "\(parser.manifest.id) relative/absolute event counts must match"
            )
        }

        let engine = ForensicsEngine()
        let relAll = try engine.parse(source: ImageSource.infer(from: relativeRoot))
        let absAll = try engine.parse(source: ImageSource.infer(from: absoluteRoot))
        XCTAssertEqual(relAll.count, absAll.count, "full engine relative/absolute parity")
    }
}
