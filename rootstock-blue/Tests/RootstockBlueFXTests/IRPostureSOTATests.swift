import XCTest
@testable import RootstockBlueFX
@testable import RootstockBlueCore
@testable import RootstockBlueCase

/// coverage IR posture: FileVault / Firewall / SIP / XProtect / FDA offline honesty + case write.
final class IRPostureSOTATests: XCTestCase {
    var relativeRoot: URL {
        URL(fileURLWithPath: "Fixtures/artifacts/macos_sample")
    }

    func testOfflinePostureFromSecurityPostureJSON() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let posture = relativeRoot.appendingPathComponent("Library/Preferences/security_posture.json")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: posture.path))

        let events = try HostIRPosture.enumerateOffline(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty)
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "IRPOSTURE" })
        XCTAssertTrue(events.allSatisfy { !$0.entityRefs.isEmpty }, "entityRefs must be non-empty")

        // Existing security products still found
        XCTAssertTrue(events.contains { $0.eventType == "ir.posture.security_product" })

        let protections = events.filter { $0.eventType == "ir.posture.protection" }
        let names = Set(protections.compactMap { $0.fields["protection.name"] })
        XCTAssertTrue(names.contains("FileVault"), "expected FileVault from security_posture.json")
        XCTAssertTrue(names.contains("Firewall"), "expected Firewall from security_posture.json and/or alf")
        XCTAssertTrue(names.contains("SIP"), "expected SIP from security_posture.json")

        // FileVault disabled in fixture
        XCTAssertTrue(protections.contains {
            $0.fields["protection.name"] == "FileVault" && $0.fields["protection.enabled"] == "false"
        })
        // Firewall off (globalstate=0 and json false)
        XCTAssertTrue(protections.contains {
            $0.fields["protection.name"] == "Firewall" && $0.fields["protection.enabled"] == "false"
        })
        // XProtect / MRT versions
        XCTAssertTrue(protections.contains {
            $0.fields["protection.name"] == "XProtect" && ($0.fields["protection.xprotect_version"] ?? "") == "5280"
        })
        XCTAssertTrue(protections.contains {
            $0.fields["protection.name"] == "MRT" && ($0.fields["protection.mrt_version"] ?? "") == "1.93"
        })

        // FDA offline honesty
        let fda = events.filter { $0.eventType == "ir.posture.fda_hint" }
        XCTAssertFalse(fda.isEmpty, "expected ir.posture.fda_hint")
        XCTAssertTrue(fda.contains { ($0.fields["protection.fda_offline_note"] ?? "").contains("live") })
    }

    func testOfflinePostureWriteToCaseStillWorks() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try HostIRPosture.enumerateOffline(source: .directory(relativeRoot))
        let scratch = FileManager.default.temporaryDirectory
            .appendingPathComponent("ir-sota-\(UUID().uuidString).rsbcase")
        defer { try? FileManager.default.removeItem(at: scratch) }
        let pkg = try CasePackage.create(at: scratch, name: "ir-sota")
        let n = try HostIRPosture.writeToCase(events, package: pkg, mode: "offline")
        XCTAssertEqual(n, events.count)
        let loaded = try pkg.loadAllEvents()
        XCTAssertTrue(loaded.contains { $0.eventType == "ir.posture.protection" })
        XCTAssertTrue(loaded.contains { $0.fields["protection.name"] == "FileVault" })
    }

    func testPersistenceInventoryTagsAutostart() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try PersistenceInventory.enumerate(source: .directory(relativeRoot))
        if !events.isEmpty {
            XCTAssertTrue(events.allSatisfy { ($0.fields["inventory.unified"] ?? "") == "true" })
            let sources = Set(events.compactMap { $0.fields["inventory.source"] })
            let expectedSources: Set<String> = ["autostart", "btm", "cron", "login_item", "ssh"]
            XCTAssertFalse(sources.intersection(expectedSources).isEmpty, "expected inventory.source tags, got \(sources)")
            let parsers = Set(events.compactMap { $0.fields["inventory.parser"] })
            let expectedParsers: Set<String> = ["AUTOSTART", "BTM", "CRON", "LOGINITEMS"]
            XCTAssertFalse(parsers.intersection(expectedParsers).isEmpty)
        }
    }

    func testLivePostureProbesDoNotCrash() {
        // Fail-soft: may or may not get FileVault/Firewall/SIP depending on host rights
        let events = HostIRPosture.enumerateLive(runStatusProbes: true)
        XCTAssertFalse(events.isEmpty)
        XCTAssertTrue(events.contains { $0.eventType == "ir.posture.host" })
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "IRPOSTURE" })
    }
}
