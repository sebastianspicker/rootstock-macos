import XCTest
@testable import RootstockBlueFX
@testable import RootstockBlueCore
@testable import RootstockBlueCase
@testable import RootstockBlueDetect

/// Wave-16 multi-plane red↔blue pairs (25 themes / 50 half-pairs beyond Wave-15).
final class Wave16MultiPlanePairTests: XCTestCase {
    var relativeRoot: URL { URL(fileURLWithPath: "Fixtures/artifacts/macos_sample") }
    var absoluteRoot: URL { relativeRoot.standardizedFileURL.resolvingSymlinksInPath() }
    private let wave16IDs = [
        "AIRPLAYRX",
        "HANDOFFCB",
        "IMSGPATH",
        "FTCAM",
        "FNDSYNC",
        "FPDOM",
        "NOTICTR",
        "SIRISUG",
        "SPIMP",
        "CTPATH",
        "CALDAV",
        "REMCLOUD",
        "MAPSLOC",
        "WTHRWDG",
        "MUSLIB",
        "BKPATH",
        "PODPATH",
        "TVPATH",
        "HKPATH",
        "HLTHPATH",
        "WLTPASS",
        "FMPATH",
        "SCICLOUD",
        "MDMPROF",
        "SUCAT"
    ]
    private let wave16HardenControls = [
        "airplay_receiver_surface",
        "handoff_clipboard_depth",
        "imessage_path_plane",
        "facetime_camera_surface",
        "finder_sync_extension",
        "fileprovider_domain",
        "notification_center_depth",
        "siri_suggestions_plane",
        "spotlight_importer_depth",
        "contacts_path_plane",
        "calendar_server_path",
        "reminders_cloud_path",
        "maps_location_path",
        "weather_widget_path",
        "music_library_path",
        "books_path_plane",
        "podcasts_path_plane",
        "tv_app_path_plane",
        "homekit_path_plane",
        "health_path_plane",
        "wallet_pass_path",
        "findmy_path_plane",
        "shortcuts_icloud_sync",
        "devicemanagement_profile",
        "softwareupdate_catalog"
    ]

    func testPluginRuntimeIncludesWave16Parsers() {
        let ids = Set(PluginRuntime().parserIDs())
        for id in wave16IDs { XCTAssertTrue(ids.contains(id), "missing \(id)") }
        XCTAssertTrue(ids.contains("SHELLPLUGINMGR"))
        XCTAssertTrue(ids.contains("PHOTOSLIBRARY"))
    }

    func testWave16ParsersEmitEventsFromFixtures() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let parsers: [any ArtifactParser] = [
            AirplayReceiverSurfaceParser(),
            HandoffClipboardDepthParser(),
            ImessagePathPlaneParser(),
            FacetimeCameraSurfaceParser(),
            FinderSyncExtensionParser(),
            FileproviderDomainParser(),
            NotificationCenterDepthParser(),
            SiriSuggestionsPlaneParser(),
            SpotlightImporterDepthParser(),
            ContactsPathPlaneParser(),
            CalendarServerPathParser(),
            RemindersCloudPathParser(),
            MapsLocationPathParser(),
            WeatherWidgetPathParser(),
            MusicLibraryPathParser(),
            BooksPathPlaneParser(),
            PodcastsPathPlaneParser(),
            TvAppPathPlaneParser(),
            HomekitPathPlaneParser(),
            HealthPathPlaneParser(),
            WalletPassPathParser(),
            FindmyPathPlaneParser(),
            ShortcutsIcloudSyncParser(),
            DevicemanagementProfileParser(),
            SoftwareupdateCatalogParser()
        ]
        for parser in parsers {
            let events = try parser.parse(source: .directory(relativeRoot))
            XCTAssertFalse(events.isEmpty, "\(parser.manifest.id)")
            XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == parser.manifest.id })
            for e in events {
                XCTAssertFalse(e.fields.values.joined(separator: " ").lowercased().contains("password=secret"))
                if let exp = e.fields.first(where: { $0.key.hasSuffix("secrets_exported") })?.value {
                    XCTAssertEqual(exp, "false")
                }
            }
        }
    }

    func testRelativeAbsoluteParityWave16() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let parsers: [any ArtifactParser] = [
            AirplayReceiverSurfaceParser(),
            HandoffClipboardDepthParser(),
            ImessagePathPlaneParser(),
            FacetimeCameraSurfaceParser(),
            FinderSyncExtensionParser(),
            FileproviderDomainParser(),
            NotificationCenterDepthParser(),
            SiriSuggestionsPlaneParser(),
            SpotlightImporterDepthParser(),
            ContactsPathPlaneParser(),
            CalendarServerPathParser(),
            RemindersCloudPathParser(),
            MapsLocationPathParser(),
            WeatherWidgetPathParser(),
            MusicLibraryPathParser(),
            BooksPathPlaneParser(),
            PodcastsPathPlaneParser(),
            TvAppPathPlaneParser(),
            HomekitPathPlaneParser(),
            HealthPathPlaneParser(),
            WalletPassPathParser(),
            FindmyPathPlaneParser(),
            ShortcutsIcloudSyncParser(),
            DevicemanagementProfileParser(),
            SoftwareupdateCatalogParser()
        ]
        for parser in parsers {
            let rel = try parser.parse(source: .directory(relativeRoot))
            let abs = try parser.parse(source: .directory(absoluteRoot))
            XCTAssertEqual(rel.count, abs.count, parser.manifest.id)
            XCTAssertFalse(rel.isEmpty)
        }
    }

    func testHardenAssessSyntheticEmitsTwentyFiveWave16Controls() {
        let synthetic = HardeningTestFixtures.planeEvents(wave: "wave16", specifications: [
            .init(plugin: "AIRPLAYRX", eventType: "airplay.receiver", fieldPrefix: "airplayrx", fileName: "airplay_receiver_surface.json", name: "AirPlay receiver dual-use", riskTag: "airplay_surface"),
            .init(plugin: "HANDOFFCB", eventType: "handoff.clipboard", fieldPrefix: "hdoffcb", fileName: "handoff_clipboard_depth.json", name: "Handoff clipboard depth", riskTag: "handoff_surface"),
            .init(plugin: "IMSGPATH", eventType: "imessage.path", fieldPrefix: "imsgpath", fileName: "imessage_path_plane.json", name: "iMessage path plane", riskTag: "imessage_surface"),
            .init(plugin: "FTCAM", eventType: "facetime.camera", fieldPrefix: "ftcam", fileName: "facetime_camera_surface.json", name: "FaceTime camera dual-use", riskTag: "facetime_surface"),
            .init(plugin: "FNDSYNC", eventType: "finder.sync_ext", fieldPrefix: "fndsync", fileName: "finder_sync_extension.json", name: "Finder Sync dual-use", riskTag: "finder_sync_surface"),
            .init(plugin: "FPDOM", eventType: "fileprovider.domain", fieldPrefix: "fpdom", fileName: "fileprovider_domain.json", name: "File Provider domain", riskTag: "fileprovider_surface"),
            .init(plugin: "NOTICTR", eventType: "notification.center", fieldPrefix: "notictr", fileName: "notification_center_depth.json", name: "Notification Center depth", riskTag: "notification_surface"),
            .init(plugin: "SIRISUG", eventType: "siri.suggestions", fieldPrefix: "sirisug", fileName: "siri_suggestions_plane.json", name: "Siri Suggestions residual", riskTag: "siri_surface"),
            .init(plugin: "SPIMP", eventType: "spotlight.importer", fieldPrefix: "spimp", fileName: "spotlight_importer_depth.json", name: "Spotlight importer depth", riskTag: "spotlight_importer_surface"),
            .init(plugin: "CTPATH", eventType: "contacts.path", fieldPrefix: "ctpath", fileName: "contacts_path_plane.json", name: "Contacts path plane", riskTag: "contacts_surface"),
            .init(plugin: "CALDAV", eventType: "calendar.caldav", fieldPrefix: "caldav", fileName: "calendar_server_path.json", name: "Calendar CalDAV residual", riskTag: "caldav_surface"),
            .init(plugin: "REMCLOUD", eventType: "reminders.cloud", fieldPrefix: "remcloud", fileName: "reminders_cloud_path.json", name: "Reminders cloud path", riskTag: "reminders_cloud_surface"),
            .init(plugin: "MAPSLOC", eventType: "maps.location", fieldPrefix: "mapsloc", fileName: "maps_location_path.json", name: "Maps location residual", riskTag: "maps_location_surface"),
            .init(plugin: "WTHRWDG", eventType: "weather.widget", fieldPrefix: "wthrwdg", fileName: "weather_widget_path.json", name: "Weather widget residual", riskTag: "weather_surface"),
            .init(plugin: "MUSLIB", eventType: "music.library", fieldPrefix: "muslib", fileName: "music_library_path.json", name: "Music library path", riskTag: "music_surface"),
            .init(plugin: "BKPATH", eventType: "books.path", fieldPrefix: "bkpath", fileName: "books_path_plane.json", name: "Books path plane", riskTag: "books_surface"),
            .init(plugin: "PODPATH", eventType: "podcasts.path", fieldPrefix: "podpath", fileName: "podcasts_path_plane.json", name: "Podcasts path plane", riskTag: "podcasts_surface"),
            .init(plugin: "TVPATH", eventType: "tv.path", fieldPrefix: "tvpath", fileName: "tv_app_path_plane.json", name: "TV.app path plane", riskTag: "tv_surface"),
            .init(plugin: "HKPATH", eventType: "homekit.path", fieldPrefix: "hkpath", fileName: "homekit_path_plane.json", name: "HomeKit path plane", riskTag: "homekit_surface"),
            .init(plugin: "HLTHPATH", eventType: "health.path", fieldPrefix: "hlthpath", fileName: "health_path_plane.json", name: "Health path plane", riskTag: "health_surface"),
            .init(plugin: "WLTPASS", eventType: "wallet.pass", fieldPrefix: "wltpass", fileName: "wallet_pass_path.json", name: "Wallet pass path", riskTag: "wallet_surface"),
            .init(plugin: "FMPATH", eventType: "findmy.path", fieldPrefix: "fmpath", fileName: "findmy_path_plane.json", name: "Find My path plane", riskTag: "findmy_surface"),
            .init(plugin: "SCICLOUD", eventType: "shortcuts.icloud", fieldPrefix: "scicloud", fileName: "shortcuts_icloud_sync.json", name: "Shortcuts iCloud sync", riskTag: "shortcuts_icloud_surface"),
            .init(plugin: "MDMPROF", eventType: "mdm.profile_depth", fieldPrefix: "mdmprof", fileName: "devicemanagement_profile.json", name: "Device management profile", riskTag: "device_mgmt_surface"),
            .init(plugin: "SUCAT", eventType: "softwareupdate.catalog", fieldPrefix: "sucat", fileName: "softwareupdate_catalog.json", name: "Software Update catalog", riskTag: "softwareupdate_surface"),
        ])
        let findings = HardeningAssessment.assess(events: synthetic)
        let controls = Set(findings.map(\.control))
        for control in wave16HardenControls {
            XCTAssertTrue(controls.contains(control), "missing \(control)")
        }
        for finding in findings where wave16HardenControls.contains(finding.control) {
            XCTAssertFalse(finding.remediation.isEmpty)
        }
    }

    func testWave16DetectionFixturesViaFixtureRunner() throws {
        let rulesDir = URL(fileURLWithPath: "Content/detections/samples")
        let fixturesDir = rulesDir.appendingPathComponent("fixtures")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: rulesDir.path))
        let wave16Rules = [
            "airplay_receiver_surface.yaml",
            "handoff_clipboard_depth.yaml",
            "imessage_path_plane.yaml",
            "facetime_camera_surface.yaml",
            "finder_sync_extension.yaml",
            "fileprovider_domain.yaml",
            "notification_center_depth.yaml",
            "siri_suggestions_plane.yaml",
            "spotlight_importer_depth.yaml",
            "contacts_path_plane.yaml",
            "calendar_server_path.yaml",
            "reminders_cloud_path.yaml",
            "maps_location_path.yaml",
            "weather_widget_path.yaml",
            "music_library_path.yaml",
            "books_path_plane.yaml",
            "podcasts_path_plane.yaml",
            "tv_app_path_plane.yaml",
            "homekit_path_plane.yaml",
            "health_path_plane.yaml",
            "wallet_pass_path.yaml",
            "findmy_path_plane.yaml",
            "shortcuts_icloud_sync.yaml",
            "devicemanagement_profile.yaml",
            "softwareupdate_catalog.yaml"
        ]
        var hitIDs: [String] = []
        for name in wave16Rules {
            let rule = try RuleLoader.load(from: rulesDir.appendingPathComponent(name))
            let events = try FixtureRunner.loadEvents(from: fixturesDir.appendingPathComponent(rule.fixture))
            let findings = FixtureRunner.evaluate(rule: rule, events: events)
            XCTAssertFalse(findings.isEmpty, "\(rule.id)")
            XCTAssertEqual(findings.first?.ruleID, rule.id)
            hitIDs.append(rule.id)
        }
        print("WAVE16_DETECTION_RULE_IDS=" + hitIDs.joined(separator: ","))
        print("WAVE16_HALF_PAIRS=" + String(wave16IDs.count * 2))
    }

    func testMissingMarkersReturnEmptyWave16() throws {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("wave16-empty-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }
        XCTAssertEqual(try AirplayReceiverSurfaceParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try HandoffClipboardDepthParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try ImessagePathPlaneParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try FacetimeCameraSurfaceParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try FinderSyncExtensionParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try FileproviderDomainParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try NotificationCenterDepthParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try SiriSuggestionsPlaneParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try SpotlightImporterDepthParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try ContactsPathPlaneParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try CalendarServerPathParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try RemindersCloudPathParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try MapsLocationPathParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try WeatherWidgetPathParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try MusicLibraryPathParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try BooksPathPlaneParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try PodcastsPathPlaneParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try TvAppPathPlaneParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try HomekitPathPlaneParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try HealthPathPlaneParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try WalletPassPathParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try FindmyPathPlaneParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try ShortcutsIcloudSyncParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try DevicemanagementProfileParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try SoftwareupdateCatalogParser().parse(source: .directory(tmp)).count, 0)
    }
}
