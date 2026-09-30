import Foundation
import RootstockBlueCore

/// Input-key policy for a surface-marker parser.
///
/// Each parser names exactly one policy. The policies are fixed so adding a
/// parser, or a key to one policy, cannot silently widen the input accepted or
/// the fields emitted by parsers on the other policy.
struct SurfaceMarkerKeys: Sendable {
    /// Keys that let a single top-level JSON object count as one record.
    let identityKeys: [String]
    /// First present key becomes `<prefix>.path`.
    let pathKeys: [String]
    /// First present key becomes `<prefix>.name`.
    let nameKeys: [String]
    /// Emit `url_host`, `share_url`, `depth`, `runs_script`, and `tool_present`.
    let emitsOptionalFields: Bool

    static let standard = SurfaceMarkerKeys(
        identityKeys: ["path", "name", "label", "kind"],
        pathKeys: ["path", "tool_path"],
        nameKeys: ["name", "kind", "label"],
        emitsOptionalFields: false
    )

    static let extended = SurfaceMarkerKeys(
        identityKeys: ["path", "name", "label", "kind", "tile_path", "share_url"],
        pathKeys: ["path", "tile_path", "handler_path", "tool_path"],
        nameKeys: ["name", "rule_name", "kind", "label"],
        emitsOptionalFields: true
    )
}

/// Everything that distinguishes one surface-marker parser from another.
///
/// The event type doubles as the identity kind, the manifest ID as the source
/// plugin label, and the field prefix as the entity prefix.
struct SurfaceMarkerSpec: Sendable {
    let manifest: PluginManifest
    /// Reads `<stem>.json` and `<stem>.jsonl` anywhere under the artifact root.
    let fileStem: String
    let fieldPrefix: String
    let eventType: String
    let defaultRiskTag: String
    let defaultNotes: String
    let keys: SurfaceMarkerKeys

    init(
        manifest: PluginManifest,
        fileStem: String,
        fieldPrefix: String,
        eventType: String,
        defaultRiskTag: String,
        defaultNotes: String,
        keys: SurfaceMarkerKeys = .standard
    ) {
        self.manifest = manifest
        self.fileStem = fileStem
        self.fieldPrefix = fieldPrefix
        self.eventType = eventType
        self.defaultRiskTag = defaultRiskTag
        self.defaultNotes = defaultNotes
        self.keys = keys
    }
}

/// A parser defined entirely by its `SurfaceMarkerSpec`. Records only emit
/// allowlisted marker fields; secret-bearing input keys are never copied.
protocol SurfaceMarkerParser: ArtifactParser {
    static var spec: SurfaceMarkerSpec { get }
}

extension SurfaceMarkerParser {
    public var manifest: PluginManifest {
        Self.spec.manifest
    }

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        SurfaceMarkerEngine.parse(source: source, spec: Self.spec)
    }
}

enum SurfaceMarkerEngine {
    private static let nestedKeys = ["items", "entries", "surfaces", "paths"]

    static func parse(source: ImageSource, spec: SurfaceMarkerSpec) -> [EventEnvelope] {
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

    private static func events(in url: URL, spec: SurfaceMarkerSpec) -> [EventEnvelope] {
        let items: [[String: Any]]
        if url.pathExtension == "jsonl" {
            items = ArtifactIO.jsonlDictionaries(contentsOf: url)
        } else {
            items = ArtifactIO.jsonDictionaryEntries(
                contentsOf: url,
                nestedKeys: nestedKeys,
                identityKeys: spec.keys.identityKeys
            )
        }
        return items.compactMap { event(from: $0, sourceURL: url, spec: spec) }
    }

    private static func event(from item: [String: Any], sourceURL: URL, spec: SurfaceMarkerSpec) -> EventEnvelope? {
        let path = firstString(in: item, keys: spec.keys.pathKeys)
        let name = firstString(in: item, keys: spec.keys.nameKeys)
        guard !path.isEmpty || !name.isEmpty else { return nil }

        let prefix = spec.fieldPrefix
        let user = stringish(item["user"]) ?? inferUser(from: path) ?? inferUser(from: sourceURL.path) ?? ""
        var fields: [String: String] = [
            "\(prefix).path": path,
            "\(prefix).name": name,
            "\(prefix).notes": stringish(item["notes"]) ?? spec.defaultNotes,
            "\(prefix).risk_tags": riskTags(in: item, defaultTag: spec.defaultRiskTag).joined(separator: ","),
            "\(prefix).secrets_exported": "false",
            FieldTaxonomy.eventType: spec.eventType,
            FieldTaxonomy.userName: user,
        ]
        if spec.keys.emitsOptionalFields {
            addOptionalFields(from: item, to: &fields, prefix: prefix)
        }
        return EventEnvelope(
            identity: EventEnvelope.Identity(kind: spec.eventType, label: spec.manifest.id),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: parseDate(item["timestamp"] ?? item["seen_at"]) ?? Date(),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "\(prefix)|\(name.isEmpty ? path : name)")],
                properties: fields,
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.88
            )
        )
    }

    private static func addOptionalFields(from item: [String: Any], to fields: inout [String: String], prefix: String) {
        if let host = stringish(item["url_host"]) { fields["\(prefix).url_host"] = host }
        if let share = stringish(item["share_url"]) { fields["\(prefix).share_url"] = share }
        if let depth = stringish(item["depth"]) { fields["\(prefix).depth"] = depth }
        if boolish(item["runs_script"]) == true { fields["\(prefix).runs_script"] = "true" }
        if boolish(item["tool_present"]) == true { fields["\(prefix).tool_present"] = "true" }
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
