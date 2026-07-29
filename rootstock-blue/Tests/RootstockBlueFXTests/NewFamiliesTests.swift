import XCTest
@testable import RootstockBlueFX
@testable import RootstockBlueCore
@testable import RootstockBlueCase

/// New DFIR families (BASICINFO, INSTALLHISTORY, DOCK) + IR posture - shipped parse path.
final class NewFamiliesTests: XCTestCase {
    var relativeRoot: URL {
        URL(fileURLWithPath: "Fixtures/artifacts/macos_sample")
    }

    var absoluteRoot: URL {
        relativeRoot.standardizedFileURL.resolvingSymlinksInPath()
    }

    func testBasicInfoParserEmitsHostFields() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try BasicInfoParser().parse(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty, "BASICINFO must emit ≥1 event")
        let basic = events.filter { $0.eventType == "host.basic_info" }
        XCTAssertFalse(basic.isEmpty, "expected host.basic_info")
        XCTAssertTrue(basic.contains { ($0.fields["host.os_version"] ?? "").hasPrefix("14.") })
        XCTAssertTrue(basic.contains { ($0.fields["host.os_build"] ?? "") == "23G93" })
        XCTAssertTrue(basic.contains { ($0.fields["host.product_name"] ?? "").contains("macOS") })
        XCTAssertTrue(basic.allSatisfy { $0.sourcePlugin == "BASICINFO" })
        XCTAssertFalse(basic[0].entityRefs.isEmpty, "entity refs required")
        XCTAssertTrue(basic[0].entityRefs.contains { $0.kind == .host })

        let identity = events.filter { $0.eventType == "host.identity" }
        XCTAssertFalse(identity.isEmpty, "expected host.identity from SystemConfiguration")
        XCTAssertTrue(identity.contains { ($0.fields["host.computer_name"] ?? "") == "alice-mbp" })
    }

    func testInstallHistoryParserEmitsPackageFields() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try InstallHistoryParser().parse(source: .directory(relativeRoot))
        XCTAssertGreaterThanOrEqual(events.count, 2)
        XCTAssertTrue(events.allSatisfy { $0.eventType == "software.install" })
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "INSTALLHISTORY" })
        XCTAssertTrue(events.contains {
            ($0.fields["software.display_name"] ?? "").contains("Suspicious Remote Tool")
        })
        XCTAssertTrue(events.contains {
            ($0.fields["software.package_identifiers"] ?? "").contains("com.evil.remotetool")
        })
        XCTAssertTrue(events.contains {
            ($0.fields["software.version"] ?? "") == "1.2.3"
        })
        XCTAssertFalse(events[0].entityRefs.isEmpty)
    }

    func testDockParserEmitsAppsAndRecent() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try DockParser().parse(source: .directory(relativeRoot))
        XCTAssertGreaterThanOrEqual(events.count, 3, "persistent apps + recent + other")
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "DOCK" })
        let dockItems = events.filter { $0.eventType == "dock.item" }
        let mru = events.filter { $0.eventType == "mru.app" }
        XCTAssertFalse(dockItems.isEmpty)
        XCTAssertFalse(mru.isEmpty)
        XCTAssertTrue(dockItems.contains { ($0.fields["dock.label"] ?? "") == "Safari"
            || ($0.fields["dock.bundle_id"] ?? "").contains("Safari") })
        XCTAssertTrue(mru.contains { ($0.fields["dock.path"] ?? "").contains("/tmp/evil_payload")
            || ($0.fields["dock.label"] ?? "").contains("evil_payload") })
        XCTAssertTrue(events.contains { !$0.entityRefs.isEmpty })
        XCTAssertTrue(events.contains { $0.fields[FieldTaxonomy.userName] == "alice" })
    }

    func testNewFamiliesInDefaultEngineAndRelativeAbsoluteParity() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let engine = ForensicsEngine()
        let ids = Set(engine.runtime.parserIDs())
        for id in ["BASICINFO", "INSTALLHISTORY", "DOCK"] {
            XCTAssertTrue(ids.contains(id), "missing default parser \(id)")
        }
        let rel = try engine.parse(source: ImageSource.infer(from: relativeRoot))
        let abs = try engine.parse(source: ImageSource.infer(from: absoluteRoot))
        XCTAssertEqual(rel.count, abs.count, "relative/absolute must not double-count")

        let plugins = Set(rel.map(\.sourcePlugin))
        for id in ["BASICINFO", "INSTALLHISTORY", "DOCK", "SAFARI", "TCC"] {
            XCTAssertTrue(plugins.contains(id), "engine output missing \(id)")
        }
    }

    func testIRPostureOfflineWritesSecurityProducts() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let events = try HostIRPosture.enumerateOffline(source: .directory(relativeRoot))
        XCTAssertFalse(events.isEmpty)
        XCTAssertTrue(events.contains { $0.eventType == "ir.posture.host" })
        XCTAssertTrue(events.contains { $0.eventType == "ir.posture.security_product" })
        XCTAssertTrue(events.contains {
            ($0.fields["security.product"] ?? "").contains("CrowdStrike")
                || ($0.fields["security.product"] ?? "").contains("Santa")
        })
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "IRPOSTURE" })
        XCTAssertTrue(events.contains { !$0.entityRefs.isEmpty })

        let scratch = FileManager.default.temporaryDirectory
            .appendingPathComponent("ir-posture-\(UUID().uuidString).rsbcase")
        defer { try? FileManager.default.removeItem(at: scratch) }
        let pkg = try CasePackage.create(at: scratch, name: "ir-test")
        let n = try HostIRPosture.writeToCase(events, package: pkg, mode: "offline")
        XCTAssertEqual(n, events.count)
        let loaded = try pkg.loadAllEvents()
        XCTAssertTrue(loaded.contains { $0.sourcePlugin == "IRPOSTURE" })
        let db = try pkg.openDatabase()
        let rows = try db.queryRows(
            "SELECT COUNT(*) AS c FROM timeline_events WHERE source_plugin='IRPOSTURE';"
        )
        let count = Int(rows.first?["c"] ?? "0") ?? 0
        XCTAssertGreaterThan(count, 0)
    }

    func testIRPostureLiveEmitsHost() {
        let events = HostIRPosture.enumerateLive(runStatusProbes: false)
        XCTAssertFalse(events.isEmpty)
        XCTAssertTrue(events.contains { $0.eventType == "ir.posture.host" })
        XCTAssertTrue(events.contains { ($0.fields["ir.mode"] ?? "") == "live" })
        XCTAssertTrue(events.contains { !($0.fields["host.os_version"] ?? "").isEmpty })
    }
}
