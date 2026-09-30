import Foundation
import Testing
import RootstockBlueCore
import RootstockBlueFX

/// Pins the exact event output of every surface-marker parser against
/// checked-in goldens so the shared engine cannot widen or narrow any parser.
///
/// Set `ROOTSTOCK_BLUE_RECORD_SURFACE_MARKERS=1` to rewrite the goldens; only
/// do that for an intentional, reviewed output change.
@Suite struct SurfaceMarkerCharacterizationTests {
    struct Case: Sendable, CustomTestStringConvertible {
        let stem: String
        let parser: any ArtifactParser
        var testDescription: String { stem }
    }

    static let cases: [Case] = [
        // Former per-file parsers.
        Case(stem: "automator_workflow", parser: AutomatorWorkflowParser()),
        Case(stem: "bluetooth_continuity_depth", parser: BluetoothContinuityDepthParser()),
        Case(stem: "calendar_reminders_automation", parser: CalendarRemindersAutomationParser()),
        Case(stem: "cron_at_job_depth", parser: CronAtJobDepthParser()),
        Case(stem: "cups_print_dualuse", parser: CupsPrintDualUseParser()),
        Case(stem: "dns_resolver_dualuse", parser: DnsResolverDualuseParser()),
        Case(stem: "emond_legacy_depth", parser: EmondLegacyDepthParser()),
        Case(stem: "font_validation_dualuse", parser: FontValidationDualuseParser()),
        Case(stem: "gatekeeper_assessment_history", parser: GatekeeperAssessmentHistoryParser()),
        Case(stem: "homebrew_package_dualuse", parser: HomebrewPackageDualUseParser()),
        Case(stem: "icloud_drive_path", parser: IcloudDrivePathParser()),
        Case(stem: "keychain_acl_path", parser: KeychainAclPathParser()),
        Case(stem: "ls_quarantine_db_depth", parser: LsQuarantineDbDepthParser()),
        Case(stem: "notes_metadata_plane", parser: NotesMetadataPlaneParser()),
        Case(stem: "pam_auth_module", parser: PamAuthModuleParser()),
        Case(stem: "photos_library_path", parser: PhotosLibraryPathParser()),
        Case(stem: "python_runtime_dualuse", parser: PythonRuntimeDualuseParser()),
        Case(stem: "quicklook_cache_depth", parser: QuicklookCacheDepthParser()),
        Case(stem: "sandbox_container_depth", parser: SandboxContainerDepthParser()),
        Case(stem: "screencapture_privacy_dualuse", parser: ScreenCapturePrivacyDualUseParser()),
        Case(stem: "screen_sharing_ard_depth", parser: ScreenSharingArdDepthParser()),
        Case(stem: "shell_plugin_manager", parser: ShellPluginManagerParser()),
        Case(stem: "tm_local_snapshot_depth", parser: TmLocalSnapshotDepthParser()),
        Case(stem: "vpn_config_dualuse", parser: VpnConfigDualuseParser()),
        Case(stem: "xpc_mach_service_depth", parser: XpcMachServiceDepthParser()),
        // Former registry-driven parsers.
        Case(stem: "airplay_receiver_surface", parser: AirplayReceiverSurfaceParser()),
        Case(stem: "handoff_clipboard_depth", parser: HandoffClipboardDepthParser()),
        Case(stem: "imessage_path_plane", parser: ImessagePathPlaneParser()),
        Case(stem: "facetime_camera_surface", parser: FacetimeCameraSurfaceParser()),
        Case(stem: "finder_sync_extension", parser: FinderSyncExtensionParser()),
        Case(stem: "fileprovider_domain", parser: FileproviderDomainParser()),
        Case(stem: "notification_center_depth", parser: NotificationCenterDepthParser()),
        Case(stem: "siri_suggestions_plane", parser: SiriSuggestionsPlaneParser()),
        Case(stem: "spotlight_importer_depth", parser: SpotlightImporterDepthParser()),
        Case(stem: "contacts_path_plane", parser: ContactsPathPlaneParser()),
        Case(stem: "calendar_server_path", parser: CalendarServerPathParser()),
        Case(stem: "reminders_cloud_path", parser: RemindersCloudPathParser()),
        Case(stem: "maps_location_path", parser: MapsLocationPathParser()),
        Case(stem: "weather_widget_path", parser: WeatherWidgetPathParser()),
        Case(stem: "music_library_path", parser: MusicLibraryPathParser()),
        Case(stem: "books_path_plane", parser: BooksPathPlaneParser()),
        Case(stem: "podcasts_path_plane", parser: PodcastsPathPlaneParser()),
        Case(stem: "tv_app_path_plane", parser: TvAppPathPlaneParser()),
        Case(stem: "homekit_path_plane", parser: HomekitPathPlaneParser()),
        Case(stem: "health_path_plane", parser: HealthPathPlaneParser()),
        Case(stem: "wallet_pass_path", parser: WalletPassPathParser()),
        Case(stem: "findmy_path_plane", parser: FindmyPathPlaneParser()),
        Case(stem: "shortcuts_icloud_sync", parser: ShortcutsIcloudSyncParser()),
        Case(stem: "devicemanagement_profile", parser: DevicemanagementProfileParser()),
        Case(stem: "softwareupdate_catalog", parser: SoftwareupdateCatalogParser()),
        // Former builder-backed parsers with extended keys and optional fields.
        Case(stem: "webloc_inetloc_delivery", parser: WeblocInetlocParser()),
        Case(stem: "mail_rules_automation", parser: MailRulesAutomationParser()),
        Case(stem: "unified_log_observation", parser: UnifiedLogObservationParser()),
        Case(stem: "dock_persistence_surface", parser: DockPersistenceSurfaceParser()),
        Case(stem: "osascript_scpt_delivery", parser: OsascriptScptDeliveryParser()),
        Case(stem: "network_share_mount", parser: NetworkShareMountParser()),
    ]

    @Test func coversEveryMarkerParserOnce() {
        #expect(Self.cases.count == 56)
        #expect(Set(Self.cases.map(\.parser.manifest.id)).count == Self.cases.count)
        #expect(Set(Self.cases.map(\.stem)).count == Self.cases.count)
    }

    @Test(arguments: SurfaceMarkerCharacterizationTests.cases)
    func outputMatchesGolden(_ testCase: Case) throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        // Nest the artifact root under a Users/<name> directory so user
        // inference from the source path is independent of the checkout path.
        let root = scratch.appendingPathComponent("Users/fallback/root", isDirectory: true)
        let empty = scratch.appendingPathComponent("Users/fallback/empty", isDirectory: true)
        try FileManager.default.createDirectory(at: empty, withIntermediateDirectories: true)
        try MarkerTree.write(stem: testCase.stem, under: root)

        let snapshot: [String: Any] = try [
            "manifest": manifestObject(testCase.parser.manifest),
            "emptyTree": run(testCase.parser, root: empty),
            "adversarialTree": run(testCase.parser, root: root),
        ]
        let data = try JSONSerialization.data(
            withJSONObject: snapshot,
            options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        ) + Data("\n".utf8)

        let golden = Self.goldenDirectory.appendingPathComponent("\(testCase.parser.manifest.id).json")
        if ProcessInfo.processInfo.environment["ROOTSTOCK_BLUE_RECORD_SURFACE_MARKERS"] == "1" {
            try FileManager.default.createDirectory(at: Self.goldenDirectory, withIntermediateDirectories: true)
            try data.write(to: golden)
        }
        let expected = try String(contentsOf: golden, encoding: .utf8)
        #expect(String(decoding: data, as: UTF8.self) == expected)
    }

    private static let goldenDirectory = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .appendingPathComponent("Fixtures/surface-markers", isDirectory: true)

    private func manifestObject(_ manifest: PluginManifest) throws -> Any {
        try JSONSerialization.jsonObject(with: JSONEncoder().encode(manifest))
    }

    /// Runs one parser and returns its events with capture-time values masked.
    /// Events are ordered by source file (stable within a file) because
    /// directory enumeration order is filesystem-defined.
    private func run(_ parser: any ArtifactParser, root: URL) throws -> [[String: Any]] {
        let rootPath = root.resolvingSymlinksInPath().path
        let started = Date()
        let events = try parser.parse(source: .directory(root))
        let finished = Date()
        let window = started...finished
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]

        let rows: [[String: Any]] = events.map { event in
            [
                "id": "<uuid>",
                "eventTime": window.contains(event.eventTime) ? "<now>" : formatter.string(from: event.eventTime),
                "collectedAt": window.contains(event.collectedAt) ? "<now>" : formatter.string(from: event.collectedAt),
                "source": event.source.rawValue,
                "sourcePlugin": event.sourcePlugin,
                "eventType": event.eventType,
                "entityRefs": event.entityRefs.map(\.description),
                "fields": event.fields,
                "rawRef": event.rawRef.map { $0.replacingOccurrences(of: rootPath, with: "<root>") } ?? NSNull(),
                "confidence": event.confidence,
            ]
        }
        let indexed = rows.enumerated().map { (offset: $0.offset, row: $0.element) }
        return indexed.sorted { lhs, rhs in
            let left = lhs.row["rawRef"] as? String ?? ""
            let right = rhs.row["rawRef"] as? String ?? ""
            return left == right ? lhs.offset < rhs.offset : left < right
        }.map(\.row)
    }
}

/// Synthetic adversarial artifact tree: every alternate path/name/identity
/// key, optional and discarded keys, missing and malformed timestamps, empty
/// and filtered risk tags, malformed JSON, and ignored file names.
private enum MarkerTree {
    static func write(stem: String, under root: URL) throws {
        try writeJSON(["items": canonicalItems, "entries": [["path": "/Users/ignored/entries"]]], to: root, "Library/Preferences/\(stem).json")
        try writeText(canonicalJSONL, to: root, "Library/Logs/\(stem).jsonl")
        // Discovered copies: identity-only single objects, a fallthrough nested
        // key, a top-level array, JSONL outside Logs, and malformed input.
        try writeJSON(["tile_path": "/private/var/tile-only", "share_url": "smb://share.example.invalid/one"], to: root, "Users/carol/Library/Vendor/TileOnly/\(stem).json")
        try writeJSON(["kind": "single-kind"], to: root, "Users/carol/Library/Vendor/KindOnly/\(stem).json")
        try writeJSON(["items": "not-an-array", "surfaces": [["label": "surface-label", "user": "dana"]]], to: root, "Users/carol/Library/Vendor/Surfaces/\(stem).json")
        try writeJSON([["path": "/Users/nia/array-entry"], ["notes": "no identity"]], to: root, "opt/data/\(stem).json")
        try writeText("{\"handler_path\":\"/opt/handler\",\"user\":\"mo\"}\n", to: root, "opt/data/\(stem).jsonl")
        try writeText("{not json", to: root, "private/var/tmp/\(stem).json")
        try writeJSON(["path": "/Users/ignored/bak"], to: root, "opt/other/\(stem).json.bak")
        try writeJSON(["path": "/Users/ignored/case"], to: root, "opt/other/\(stem.uppercased()).JSON")
    }

    static var canonicalItems: [[String: Any]] { [
        [
            "path": "/Users/alice/Library/Markers/primary",
            "tile_path": "/Users/alice/tile",
            "handler_path": "/Users/alice/handler",
            "tool_path": "/usr/local/bin/tool",
            "name": "primary-name",
            "rule_name": "rule-a",
            "kind": "kind-a",
            "label": "label-a",
            "user": "alice",
            "notes": "synthetic note",
            "risk_tags": "custom_a, password_dump_x ,Password_Dump_Upper,custom_b,custom_a",
            "url_host": "host.example.invalid",
            "share_url": "smb://share.example.invalid/x",
            "depth": 3,
            "runs_script": true,
            "tool_present": "yes",
            "timestamp": "2024-01-02T03:04:05Z",
            "seen_at": "2020-01-01T00:00:00Z",
        ].merging(discardedKeys) { current, _ in current },
        ["tile_path": "/Users/bob/tile", "rule_name": "rule-only", "handler_path": "/Users/bob/handler", "risk_tags": "", "runs_script": "false", "tool_present": false],
        ["tool_path": "/Users/erin/bin/tool", "kind": "kind-only", "seen_at": 1_700_000_000, "runs_script": "yes", "tool_present": 1],
        ["handler_path": "/Users/frank/handler", "label": "label-only", "seen_at": 1_700_000_000_123],
        ["name": 42, "user": "gina", "seen_at": 123, "depth": "deep", "url_host": 7],
        ["notes": "no identity keys", "user": "nobody"],
        ["path": "/Users/Shared/shared-marker", "risk_tags": " "],
        ["rule_name": "rule-name-only", "user": "hank", "risk_tags": ",,"],
        ["tile_path": "/private/var/tile-no-user"],
        ["path": "/Users/ivy/fractional", "timestamp": "2024-01-02T03:04:05.678Z"],
        ["path": "/Users/jack/bad-time", "timestamp": "not-a-date", "seen_at": "2021-05-06T07:08:09Z"],
        ["path": "", "name": "", "kind": "empty-strings-fall-through", "user": ""],
        ["share_url": "smb://share.example.invalid/only", "url_host": "only.example.invalid", "depth": 1],
    ] }

    static var discardedKeys: [String: Any] { [
        "password": "synthetic-password",
        "cookie": "synthetic-cookie",
        "cookie_value": "synthetic-cookie-value",
        "secret": "synthetic-secret",
        "token": "synthetic-token",
        "keychain_data": "synthetic-keychain",
        "private_key": "synthetic-key",
        "photo_blob": "synthetic-blob",
        "note_body": "synthetic-body",
        "oauth": "synthetic-oauth",
    ] }

    static let canonicalJSONL = [
        #"{"path":"/Users/kim/jsonl-one","timestamp":"2024-02-03T04:05:06Z","risk_tags":"jsonl_tag"}"#,
        "# comment line",
        "not json",
        "   ",
        "[1,2]",
        #"{"name":"jsonl-name","user":"lee","risk_tags":"password_dump"}"#,
        #"{"tile_path":"/Users/lee/jsonl-tile","runs_script":true,"depth":2}"#,
        "",
    ].joined(separator: "\n")

    private static func writeJSON(_ object: Any, to root: URL, _ relative: String) throws {
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        try write(data, to: root, relative)
    }

    private static func writeText(_ text: String, to root: URL, _ relative: String) throws {
        try write(Data(text.utf8), to: root, relative)
    }

    private static func write(_ data: Data, to root: URL, _ relative: String) throws {
        let url = root.appendingPathComponent(relative)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try data.write(to: url)
    }
}
