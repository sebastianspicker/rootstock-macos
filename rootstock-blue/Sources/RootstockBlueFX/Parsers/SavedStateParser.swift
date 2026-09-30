import Foundation
import RootstockBlueCore

/// Saved Application State inventory - which apps left restore windows/state.
///
/// Useful for pattern-of-life and for spotting non-Apple bundles with tmp-backed
/// app paths (suspicious implant UI restore).
public struct SavedStateParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "SAVEDSTATE",
        tier: .tier2,
        description: "Saved Application State inventory (bundle_id / restore paths)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var seen = PathDeduper()
        var events = parseKnownStateFiles(root: root, seen: &seen)
        events.append(contentsOf: parseSavedStateDirectories(root: root, seen: &seen))
        return events
    }

    private func parseKnownStateFiles(root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        let paths = [
            "Library/Preferences/saved_state.json",
            "Library/Preferences/saved_application_state.json",
            "Library/Logs/saved_state.jsonl",
        ]
        var events: [EventEnvelope] = []
        for path in paths {
            guard let url = root.firstExisting([path]), seen.insert(url) else { continue }
            events.append(contentsOf: parseFile(at: url))
        }
        for url in root.enumerate(matching: isSavedStateExport) where seen.insert(url) {
            events.append(contentsOf: parseFile(at: url))
        }
        return events
    }

    private func isSavedStateExport(_ url: URL) -> Bool {
        ["saved_state.json", "saved_application_state.json", "saved_state.jsonl"]
            .contains(url.lastPathComponent)
    }

    private func parseSavedStateDirectories(
        root: ArtifactRoot,
        seen: inout PathDeduper
    ) -> [EventEnvelope] {
        root.enumerate(matching: isSavedStateArtifact).compactMap { url in
            savedStateDirectoryEvent(for: url, seen: &seen)
        }
    }

    private func isSavedStateArtifact(_ url: URL) -> Bool {
        url.path.contains("Saved Application State")
            && (url.lastPathComponent.hasSuffix(".savedState")
                || url.lastPathComponent == "windows.plist"
                || url.lastPathComponent == "data.data")
    }

    private func savedStateDirectoryEvent(for url: URL, seen: inout PathDeduper) -> EventEnvelope? {
        guard let stateURL = savedStateDirectory(containing: url) else { return nil }
        let key = "savedstate-dir:" + ArtifactRoot.pathKey(stateURL)
        guard seen.insert(pathKey: key) else { return nil }

        let bundleHint = stateURL.lastPathComponent.replacingOccurrences(of: ".savedState", with: "")
        let path = ArtifactRoot.pathKey(stateURL)
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "app.saved_state",
                label: "SAVEDSTATE"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: Date(timeIntervalSince1970: 0),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [
                EntityID(kind: .host, value: "savedstate|\(bundleHint)"),
                .file(path: path),
            ],
                properties: makeFields(
                bundleID: bundleHint,
                path: path,
                appPath: "",
                risk: riskFor(bundleID: bundleHint, appPath: "")
            ),
                provenance: path,
                confidence: 0.85
            )
        )
    }

    private func savedStateDirectory(containing url: URL) -> URL? {
        if url.lastPathComponent.hasSuffix(".savedState") { return url }
        guard url.path.contains(".savedState") else { return nil }

        var current = url
        while !current.lastPathComponent.hasSuffix(".savedState"), current.path != "/" {
            current = current.deletingLastPathComponent()
        }
        return current
    }

    private func parseFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" {
            return parseJSONL(at: url)
        }
        return ArtifactIO.jsonDictionaryEntries(
            contentsOf: url,
            nestedKeys: ["states", "items", "saved_state"],
            identityKeys: ["bundle_id"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url)
            .compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let bundleID = stringish(item["bundle_id"])
            ?? stringish(item["bundleID"])
            ?? stringish(item["app_id"])
            ?? ""
        let path = stringish(item["path"])
            ?? stringish(item["state_path"])
            ?? ""
        let appPath = stringish(item["app_path"])
            ?? stringish(item["executable"])
            ?? ""
        guard !bundleID.isEmpty || !path.isEmpty else { return nil }

        var risk = riskFor(bundleID: bundleID, appPath: appPath)
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            for t in tags.split(separator: ",") {
                let s = t.trimmingCharacters(in: .whitespaces)
                if !s.isEmpty, !risk.contains(s) { risk.append(s) }
            }
        }

        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "app.saved_state",
                label: "SAVEDSTATE"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: parseDate(item["last_restored"] ?? item["mtime"]) ?? Date(timeIntervalSince1970: 0),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [
                EntityID(kind: .host, value: "savedstate|\(bundleID.isEmpty ? path : bundleID)"),
            ] + (path.isEmpty ? [] : [.file(path: path)]),
                properties: makeFields(bundleID: bundleID, path: path, appPath: appPath, risk: risk),
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.9
            )
        )
    }

    private func makeFields(bundleID: String, path: String, appPath: String, risk: [String]) -> [String: String] {
        var fields: [String: String] = [
            "savedstate.bundle_id": bundleID,
            "savedstate.path": path,
            "savedstate.app_path": appPath,
            FieldTaxonomy.eventType: "app.saved_state",
        ]
        if !risk.isEmpty {
            fields["savedstate.risk_tags"] = risk.joined(separator: ",")
        }
        return fields
    }

    private func riskFor(bundleID: String, appPath: String) -> [String] {
        let bundle = bundleID.lowercased()
        let path = appPath.lowercased()
        var risk: [String] = []

        if isSuspiciousBundle(bundle) { risk.append("suspicious_bundle") }
        if isTemporaryPath(path) { risk.append("tmp_path") }
        if isUnknownVendorBundle(bundle) { risk.append("unknown_vendor") }
        return risk
    }

    private func isSuspiciousBundle(_ bundle: String) -> Bool {
        ["evil", "implant", "malware"].contains(where: bundle.contains)
    }

    private func isTemporaryPath(_ path: String) -> Bool {
        path.contains("/tmp/") || path.hasPrefix("/var/tmp") || path.contains("/downloads/")
    }

    private func isUnknownVendorBundle(_ bundle: String) -> Bool {
        guard !bundle.isEmpty, bundle.contains("unknown") || bundle.contains("hack") else { return false }
        return !bundle.hasPrefix("com.apple.")
            && !bundle.hasPrefix("com.microsoft.")
            && !bundle.hasPrefix("com.google.")
    }
}
