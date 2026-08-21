import Foundation
import RootstockBlueCore

/// Fixed event contract for the Wave-16 parser family.
///
/// This is intentionally separate from `SurfaceMarkerEventBuilder`: Wave-16
/// accepts only its documented input keys and emits only its stable envelope
/// fields. Keeping those policies explicit prevents later marker waves from
/// accidentally widening this forensic surface.
struct Wave16ParserSpec: Sendable, Equatable {
    let fileStem: String
    let fieldPrefix: String
    let eventType: String
    let identityKind: String
    let identityLabel: String
    let entityPrefix: String
    let defaultRiskTag: String
    let defaultNotes: String
}

/// Immutable inputs used to build one Wave-16 parser registration.
private struct Wave16ParserDescriptor: Sendable {
    let manifest: PluginManifest
    let spec: Wave16ParserSpec
    let hardeningControl: String
    let hardeningName: String
    let makeParser: @Sendable () -> any ArtifactParser
}

/// Immutable registration metadata shared by the default runtime and Wave-16
/// contract tests. Individual parser implementations remain the production
/// source for their exact parsing behavior; this keeps their registration,
/// ordering, and test expectations from drifting apart.
struct Wave16ParserRegistration: Sendable {
    let manifest: PluginManifest
    let spec: Wave16ParserSpec
    let hardeningControl: String
    let hardeningName: String
    private let makeParser: @Sendable () -> any ArtifactParser

    init(
        manifest: PluginManifest,
        spec: Wave16ParserSpec,
        hardeningControl: String,
        hardeningName: String,
        makeParser: @escaping @Sendable () -> any ArtifactParser
    ) {
        self.manifest = manifest
        self.spec = spec
        self.hardeningControl = hardeningControl
        self.hardeningName = hardeningName
        self.makeParser = makeParser
    }

    func parser() -> any ArtifactParser {
        makeParser()
    }
}

/// Internal implementation shared by the 25 public Wave-16 parser wrappers.
/// The wrappers retain only their stable ID and public initializer; all mutable
/// behavior is resolved from the registry below.
protocol Wave16RegisteredArtifactParser: ArtifactParser {
    static var wave16ID: String { get }
}

extension Wave16RegisteredArtifactParser {
    public var manifest: PluginManifest {
        Wave16ParserRegistry.registration(for: Self.wave16ID).manifest
    }

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        Wave16ParserSupport.parse(
            source: source,
            spec: Wave16ParserRegistry.registration(for: Self.wave16ID).spec
        )
    }
}

/// Wave-16's single registration and expectation source. Declaration order is
/// runtime order and is part of the default parser contract.
enum Wave16ParserRegistry {
    static let registrations: [Wave16ParserRegistration] = [
        registration(Wave16ParserDescriptor(manifest: PluginManifest(id: "AIRPLAYRX", tier: .tier2, description: "AirPlay receiver dual-use markers"), spec: Wave16ParserSpec(fileStem: "airplay_receiver_surface", fieldPrefix: "airplayrx", eventType: "airplay.receiver", identityKind: "airplay.receiver", identityLabel: "AIRPLAYRX", entityPrefix: "airplayrx", defaultRiskTag: "airplay_surface", defaultNotes: "AirPlay receiver dual-use markers - never enables AirPlay Receiver or spoofs AirPlay targets"), hardeningControl: "airplay_receiver_surface", hardeningName: "AirPlay receiver dual-use", makeParser: { AirplayReceiverSurfaceParser() })),
        registration(Wave16ParserDescriptor(manifest: PluginManifest(id: "HANDOFFCB", tier: .tier2, description: "Handoff clipboard depth markers"), spec: Wave16ParserSpec(fileStem: "handoff_clipboard_depth", fieldPrefix: "hdoffcb", eventType: "handoff.clipboard", identityKind: "handoff.clipboard", identityLabel: "HANDOFFCB", entityPrefix: "hdoffcb", defaultRiskTag: "handoff_surface", defaultNotes: "Handoff clipboard depth markers - never reads Universal Clipboard contents or forges Handoff activity"), hardeningControl: "handoff_clipboard_depth", hardeningName: "Handoff clipboard depth", makeParser: { HandoffClipboardDepthParser() })),
        registration(Wave16ParserDescriptor(manifest: PluginManifest(id: "IMSGPATH", tier: .tier2, description: "iMessage path plane markers"), spec: Wave16ParserSpec(fileStem: "imessage_path_plane", fieldPrefix: "imsgpath", eventType: "imessage.path", identityKind: "imessage.path", identityLabel: "IMSGPATH", entityPrefix: "imsgpath", defaultRiskTag: "imessage_surface", defaultNotes: "iMessage path plane markers - never reads Messages database contents or exports chat transcripts"), hardeningControl: "imessage_path_plane", hardeningName: "iMessage path plane", makeParser: { ImessagePathPlaneParser() })),
        registration(Wave16ParserDescriptor(manifest: PluginManifest(id: "FTCAM", tier: .tier2, description: "FaceTime camera dual-use markers"), spec: Wave16ParserSpec(fileStem: "facetime_camera_surface", fieldPrefix: "ftcam", eventType: "facetime.camera", identityKind: "facetime.camera", identityLabel: "FTCAM", entityPrefix: "ftcam", defaultRiskTag: "facetime_surface", defaultNotes: "FaceTime camera dual-use markers - never activates camera/mic or dumps FaceTime call history contents"), hardeningControl: "facetime_camera_surface", hardeningName: "FaceTime camera dual-use", makeParser: { FacetimeCameraSurfaceParser() })),
        registration(Wave16ParserDescriptor(manifest: PluginManifest(id: "FNDSYNC", tier: .tier2, description: "Finder Sync dual-use markers"), spec: Wave16ParserSpec(fileStem: "finder_sync_extension", fieldPrefix: "fndsync", eventType: "finder.sync_ext", identityKind: "finder.sync_ext", identityLabel: "FNDSYNC", entityPrefix: "fndsync", defaultRiskTag: "finder_sync_surface", defaultNotes: "Finder Sync dual-use markers - never installs Finder Sync extensions or rewrites Finder preferences for abuse"), hardeningControl: "finder_sync_extension", hardeningName: "Finder Sync dual-use", makeParser: { FinderSyncExtensionParser() })),
        registration(Wave16ParserDescriptor(manifest: PluginManifest(id: "FPDOM", tier: .tier2, description: "File Provider domain markers"), spec: Wave16ParserSpec(fileStem: "fileprovider_domain", fieldPrefix: "fpdom", eventType: "fileprovider.domain", identityKind: "fileprovider.domain", identityLabel: "FPDOM", entityPrefix: "fpdom", defaultRiskTag: "fileprovider_surface", defaultNotes: "File Provider domain markers - never registers malicious File Provider domains or exfiltrates provider caches"), hardeningControl: "fileprovider_domain", hardeningName: "File Provider domain", makeParser: { FileproviderDomainParser() })),
        registration(Wave16ParserDescriptor(manifest: PluginManifest(id: "NOTICTR", tier: .tier2, description: "Notification Center depth markers"), spec: Wave16ParserSpec(fileStem: "notification_center_depth", fieldPrefix: "notictr", eventType: "notification.center", identityKind: "notification.center", identityLabel: "NOTICTR", entityPrefix: "notictr", defaultRiskTag: "notification_surface", defaultNotes: "Notification Center depth markers - never dumps notification body contents or forges notification payloads"), hardeningControl: "notification_center_depth", hardeningName: "Notification Center depth", makeParser: { NotificationCenterDepthParser() })),
        registration(Wave16ParserDescriptor(manifest: PluginManifest(id: "SIRISUG", tier: .tier2, description: "Siri Suggestions residual markers"), spec: Wave16ParserSpec(fileStem: "siri_suggestions_plane", fieldPrefix: "sirisug", eventType: "siri.suggestions", identityKind: "siri.suggestions", identityLabel: "SIRISUG", entityPrefix: "sirisug", defaultRiskTag: "siri_surface", defaultNotes: "Siri Suggestions residual markers - never dumps Siri transcripts or Suggestions databases contents"), hardeningControl: "siri_suggestions_plane", hardeningName: "Siri Suggestions residual", makeParser: { SiriSuggestionsPlaneParser() })),
        registration(Wave16ParserDescriptor(manifest: PluginManifest(id: "SPIMP", tier: .tier2, description: "Spotlight importer depth markers"), spec: Wave16ParserSpec(fileStem: "spotlight_importer_depth", fieldPrefix: "spimp", eventType: "spotlight.importer", identityKind: "spotlight.importer", identityLabel: "SPIMP", entityPrefix: "spimp", defaultRiskTag: "spotlight_importer_surface", defaultNotes: "Spotlight importer depth markers - never installs malicious Spotlight importers or dumps mdworker index contents"), hardeningControl: "spotlight_importer_depth", hardeningName: "Spotlight importer depth", makeParser: { SpotlightImporterDepthParser() })),
        registration(Wave16ParserDescriptor(manifest: PluginManifest(id: "CTPATH", tier: .tier2, description: "Contacts path plane markers"), spec: Wave16ParserSpec(fileStem: "contacts_path_plane", fieldPrefix: "ctpath", eventType: "contacts.path", identityKind: "contacts.path", identityLabel: "CTPATH", entityPrefix: "ctpath", defaultRiskTag: "contacts_surface", defaultNotes: "Contacts path plane markers - never exports contact cards or dumps AddressBook database contents"), hardeningControl: "contacts_path_plane", hardeningName: "Contacts path plane", makeParser: { ContactsPathPlaneParser() })),
        registration(Wave16ParserDescriptor(manifest: PluginManifest(id: "CALDAV", tier: .tier2, description: "Calendar CalDAV residual markers"), spec: Wave16ParserSpec(fileStem: "calendar_server_path", fieldPrefix: "caldav", eventType: "calendar.caldav", identityKind: "calendar.caldav", identityLabel: "CALDAV", entityPrefix: "caldav", defaultRiskTag: "caldav_surface", defaultNotes: "Calendar CalDAV residual markers - never reads calendar event bodies or credentials from CalDAV stores"), hardeningControl: "calendar_server_path", hardeningName: "Calendar CalDAV residual", makeParser: { CalendarServerPathParser() })),
        registration(Wave16ParserDescriptor(manifest: PluginManifest(id: "REMCLOUD", tier: .tier2, description: "Reminders cloud path markers"), spec: Wave16ParserSpec(fileStem: "reminders_cloud_path", fieldPrefix: "remcloud", eventType: "reminders.cloud", identityKind: "reminders.cloud", identityLabel: "REMCLOUD", entityPrefix: "remcloud", defaultRiskTag: "reminders_cloud_surface", defaultNotes: "Reminders cloud path markers - never reads reminder titles/bodies or exports Reminders databases"), hardeningControl: "reminders_cloud_path", hardeningName: "Reminders cloud path", makeParser: { RemindersCloudPathParser() })),
        registration(Wave16ParserDescriptor(manifest: PluginManifest(id: "MAPSLOC", tier: .tier2, description: "Maps location residual markers"), spec: Wave16ParserSpec(fileStem: "maps_location_path", fieldPrefix: "mapsloc", eventType: "maps.location", identityKind: "maps.location", identityLabel: "MAPSLOC", entityPrefix: "mapsloc", defaultRiskTag: "maps_location_surface", defaultNotes: "Maps location residual markers - never dumps location history or spoofs CoreLocation positions"), hardeningControl: "maps_location_path", hardeningName: "Maps location residual", makeParser: { MapsLocationPathParser() })),
        registration(Wave16ParserDescriptor(manifest: PluginManifest(id: "WTHRWDG", tier: .tier2, description: "Weather widget residual markers"), spec: Wave16ParserSpec(fileStem: "weather_widget_path", fieldPrefix: "wthrwdg", eventType: "weather.widget", identityKind: "weather.widget", identityLabel: "WTHRWDG", entityPrefix: "wthrwdg", defaultRiskTag: "weather_surface", defaultNotes: "Weather widget residual markers - never dumps weather personalization data or widget timeline contents"), hardeningControl: "weather_widget_path", hardeningName: "Weather widget residual", makeParser: { WeatherWidgetPathParser() })),
        registration(Wave16ParserDescriptor(manifest: PluginManifest(id: "MUSLIB", tier: .tier2, description: "Music library path markers"), spec: Wave16ParserSpec(fileStem: "music_library_path", fieldPrefix: "muslib", eventType: "music.library", identityKind: "music.library", identityLabel: "MUSLIB", entityPrefix: "muslib", defaultRiskTag: "music_surface", defaultNotes: "Music library path markers - never exports Music library media or DRM material"), hardeningControl: "music_library_path", hardeningName: "Music library path", makeParser: { MusicLibraryPathParser() })),
        registration(Wave16ParserDescriptor(manifest: PluginManifest(id: "BKPATH", tier: .tier2, description: "Books path plane markers"), spec: Wave16ParserSpec(fileStem: "books_path_plane", fieldPrefix: "bkpath", eventType: "books.path", identityKind: "books.path", identityLabel: "BKPATH", entityPrefix: "bkpath", defaultRiskTag: "books_surface", defaultNotes: "Books path plane markers - never extracts EPUB contents or Books annotations as bulk export"), hardeningControl: "books_path_plane", hardeningName: "Books path plane", makeParser: { BooksPathPlaneParser() })),
        registration(Wave16ParserDescriptor(manifest: PluginManifest(id: "PODPATH", tier: .tier2, description: "Podcasts path plane markers"), spec: Wave16ParserSpec(fileStem: "podcasts_path_plane", fieldPrefix: "podpath", eventType: "podcasts.path", identityKind: "podcasts.path", identityLabel: "PODPATH", entityPrefix: "podpath", defaultRiskTag: "podcasts_surface", defaultNotes: "Podcasts path plane markers - never dumps podcast episode files or account tokens"), hardeningControl: "podcasts_path_plane", hardeningName: "Podcasts path plane", makeParser: { PodcastsPathPlaneParser() })),
        registration(Wave16ParserDescriptor(manifest: PluginManifest(id: "TVPATH", tier: .tier2, description: "TV.app path plane markers"), spec: Wave16ParserSpec(fileStem: "tv_app_path_plane", fieldPrefix: "tvpath", eventType: "tv.path", identityKind: "tv.path", identityLabel: "TVPATH", entityPrefix: "tvpath", defaultRiskTag: "tv_surface", defaultNotes: "TV.app path plane markers - never dumps TV.app media caches or account material"), hardeningControl: "tv_app_path_plane", hardeningName: "TV.app path plane", makeParser: { TvAppPathPlaneParser() })),
        registration(Wave16ParserDescriptor(manifest: PluginManifest(id: "HKPATH", tier: .tier2, description: "HomeKit path plane markers"), spec: Wave16ParserSpec(fileStem: "homekit_path_plane", fieldPrefix: "hkpath", eventType: "homekit.path", identityKind: "homekit.path", identityLabel: "HKPATH", entityPrefix: "hkpath", defaultRiskTag: "homekit_surface", defaultNotes: "HomeKit path plane markers - never enumerates HomeKit accessory secrets or pairs devices"), hardeningControl: "homekit_path_plane", hardeningName: "HomeKit path plane", makeParser: { HomekitPathPlaneParser() })),
        registration(Wave16ParserDescriptor(manifest: PluginManifest(id: "HLTHPATH", tier: .tier2, description: "Health path plane markers"), spec: Wave16ParserSpec(fileStem: "health_path_plane", fieldPrefix: "hlthpath", eventType: "health.path", identityKind: "health.path", identityLabel: "HLTHPATH", entityPrefix: "hlthpath", defaultRiskTag: "health_surface", defaultNotes: "Health path plane markers - never exports HealthKit samples or medical records"), hardeningControl: "health_path_plane", hardeningName: "Health path plane", makeParser: { HealthPathPlaneParser() })),
        registration(Wave16ParserDescriptor(manifest: PluginManifest(id: "WLTPASS", tier: .tier2, description: "Wallet pass path markers"), spec: Wave16ParserSpec(fileStem: "wallet_pass_path", fieldPrefix: "wltpass", eventType: "wallet.pass", identityKind: "wallet.pass", identityLabel: "WLTPASS", entityPrefix: "wltpass", defaultRiskTag: "wallet_surface", defaultNotes: "Wallet pass path markers - never dumps pass contents, payment tokens, or card data"), hardeningControl: "wallet_pass_path", hardeningName: "Wallet pass path", makeParser: { WalletPassPathParser() })),
        registration(Wave16ParserDescriptor(manifest: PluginManifest(id: "FMPATH", tier: .tier2, description: "Find My path plane markers"), spec: Wave16ParserSpec(fileStem: "findmy_path_plane", fieldPrefix: "fmpath", eventType: "findmy.path", identityKind: "findmy.path", identityLabel: "FMPATH", entityPrefix: "fmpath", defaultRiskTag: "findmy_surface", defaultNotes: "Find My path plane markers - never queries Find My device locations or dumps owner tokens"), hardeningControl: "findmy_path_plane", hardeningName: "Find My path plane", makeParser: { FindmyPathPlaneParser() })),
        registration(Wave16ParserDescriptor(manifest: PluginManifest(id: "SCICLOUD", tier: .tier2, description: "Shortcuts iCloud sync markers"), spec: Wave16ParserSpec(fileStem: "shortcuts_icloud_sync", fieldPrefix: "scicloud", eventType: "shortcuts.icloud", identityKind: "shortcuts.icloud", identityLabel: "SCICLOUD", entityPrefix: "scicloud", defaultRiskTag: "shortcuts_icloud_surface", defaultNotes: "Shortcuts iCloud sync markers - never executes Shortcuts or dumps iCloud-synced automation databases"), hardeningControl: "shortcuts_icloud_sync", hardeningName: "Shortcuts iCloud sync", makeParser: { ShortcutsIcloudSyncParser() })),
        registration(Wave16ParserDescriptor(manifest: PluginManifest(id: "MDMPROF", tier: .tier2, description: "Device management profile markers"), spec: Wave16ParserSpec(fileStem: "devicemanagement_profile", fieldPrefix: "mdmprof", eventType: "mdm.profile_depth", identityKind: "mdm.profile_depth", identityLabel: "MDMPROF", entityPrefix: "mdmprof", defaultRiskTag: "device_mgmt_surface", defaultNotes: "Device management profile markers - never installs configuration profiles or enrolls hosts in MDM"), hardeningControl: "devicemanagement_profile", hardeningName: "Device management profile", makeParser: { DevicemanagementProfileParser() })),
        registration(Wave16ParserDescriptor(manifest: PluginManifest(id: "SUCAT", tier: .tier2, description: "Software Update catalog markers"), spec: Wave16ParserSpec(fileStem: "softwareupdate_catalog", fieldPrefix: "sucat", eventType: "softwareupdate.catalog", identityKind: "softwareupdate.catalog", identityLabel: "SUCAT", entityPrefix: "sucat", defaultRiskTag: "softwareupdate_surface", defaultNotes: "Software Update catalog markers - never points SUS catalogs at attacker mirrors or tampers with update plists"), hardeningControl: "softwareupdate_catalog", hardeningName: "Software Update catalog", makeParser: { SoftwareupdateCatalogParser() })),
    ]

    static var parsers: [any ArtifactParser] {
        registrations.map { $0.parser() }
    }

    static var expectedIDs: [String] {
        registrations.map(\.manifest.id)
    }

    private static let registrationsByID = Dictionary(
        uniqueKeysWithValues: registrations.map { ($0.manifest.id, $0) }
    )

    static func registration(for id: String) -> Wave16ParserRegistration {
        guard let registration = registrationsByID[id] else {
            preconditionFailure("Unknown Wave-16 parser ID: \(id)")
        }
        return registration
    }

    private static func registration(
        _ descriptor: Wave16ParserDescriptor
    ) -> Wave16ParserRegistration {
        Wave16ParserRegistration(
            manifest: descriptor.manifest,
            spec: descriptor.spec,
            hardeningControl: descriptor.hardeningControl,
            hardeningName: descriptor.hardeningName,
            makeParser: descriptor.makeParser
        )
    }
}

enum Wave16ParserSupport {
    private static let nestedKeys = ["items", "entries", "surfaces", "paths"]
    private static let identityKeys = ["path", "name", "label", "kind"]
    private static let pathKeys = ["path", "tool_path"]
    private static let nameKeys = ["name", "kind", "label"]

    static func parse(source: ImageSource, spec: Wave16ParserSpec) -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var urls: [URL] = []
        var seen = PathDeduper()

        appendCanonicalURLs(root: root, stem: spec.fileStem, to: &urls, seen: &seen)
        appendDiscoveredURLs(root: root, stem: spec.fileStem, to: &urls, seen: &seen)
        return urls.flatMap { events(in: $0, spec: spec) }
    }

    private static func appendCanonicalURLs(root: ArtifactRoot, stem: String, to urls: inout [URL], seen: inout PathDeduper) {
        for path in ["Library/Preferences/\(stem).json", "Library/Logs/\(stem).jsonl"] {
            if let url = root.firstExisting([path]), seen.insert(url) {
                urls.append(url)
            }
        }
    }

    private static func appendDiscoveredURLs(root: ArtifactRoot, stem: String, to urls: inout [URL], seen: inout PathDeduper) {
        let jsonName = "\(stem).json"
        let jsonlName = "\(stem).jsonl"
        for url in root.enumerate(matching: { url in
            url.lastPathComponent == jsonName || url.lastPathComponent == jsonlName
        }) where seen.insert(url) {
            urls.append(url)
        }
    }

    private static func events(in url: URL, spec: Wave16ParserSpec) -> [EventEnvelope] {
        let items: [[String: Any]]
        if url.pathExtension == "jsonl" {
            items = ArtifactIO.jsonlDictionaries(contentsOf: url)
        } else {
            items = ArtifactIO.jsonDictionaryEntries(
                contentsOf: url,
                nestedKeys: nestedKeys,
                identityKeys: identityKeys
            )
        }
        return items.compactMap { event(from: $0, sourceURL: url, spec: spec) }
    }

    private static func event(from item: [String: Any], sourceURL: URL, spec: Wave16ParserSpec) -> EventEnvelope? {
        let path = firstString(in: item, keys: pathKeys)
        let name = firstString(in: item, keys: nameKeys)
        guard !path.isEmpty || !name.isEmpty else { return nil }

        let user = stringish(item["user"]) ?? inferUser(from: path) ?? inferUser(from: sourceURL.path) ?? ""
        let fields: [String: String] = [
            "\(spec.fieldPrefix).path": path,
            "\(spec.fieldPrefix).name": name,
            "\(spec.fieldPrefix).notes": stringish(item["notes"]) ?? spec.defaultNotes,
            "\(spec.fieldPrefix).risk_tags": riskTags(in: item, defaultTag: spec.defaultRiskTag).joined(separator: ","),
            "\(spec.fieldPrefix).secrets_exported": "false",
            FieldTaxonomy.eventType: spec.eventType,
            FieldTaxonomy.userName: user,
        ]
        return EventEnvelope(
            identity: EventEnvelope.Identity(kind: spec.identityKind, label: spec.identityLabel),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: parseDate(item["timestamp"] ?? item["seen_at"]) ?? Date(),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "\(spec.entityPrefix)|\(name.isEmpty ? path : name)")],
                properties: fields,
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.88
            )
        )
    }

    private static func firstString(in item: [String: Any], keys: [String]) -> String {
        for key in keys {
            if let value = stringish(item[key]) { return value }
        }
        return ""
    }

    private static func riskTags(in item: [String: Any], defaultTag: String) -> [String] {
        var tags = (stringish(item["risk_tags"]) ?? "").split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.lowercased().contains("password_dump") }
        if !tags.contains(defaultTag) { tags.append(defaultTag) }
        return tags
    }
}
