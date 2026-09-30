import Foundation
import RootstockBlueCore

/// Trash recovery inventory from `.Trash` / `.Trashes` trees and JSON exports.
///
/// Recovers deleted filenames, original paths, and deletion times for IR narrative
/// (anti-forensics delete, credential discards, dropped payloads).
public struct TrashParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "TRASH",
        tier: .tier2,
        description: "Trash recovery inventory (original path / deleted_at / risk tags)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var seen = PathDeduper()
        var events = inventoryEvents(root: root, seen: &seen)
        events.append(contentsOf: residualTrashEvents(root: root, inventoriedNames: Set(events.compactMap { $0.fields["trash.filename"] }.filter { !$0.isEmpty }), seen: &seen))
        return events
    }

    private func inventoryEvents(root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        let paths = ["Library/Preferences/trash_inventory.json", "Library/Logs/trash_export.jsonl", "Library/Preferences/trash_export.json"]
        var events: [EventEnvelope] = []
        for path in paths {
            if let url = root.firstExisting([path]), seen.insert(url) { events.append(contentsOf: parseInventoryFile(at: url)) }
        }
        for url in root.enumerate(matching: isTrashInventoryFile) where seen.insert(url) {
            events.append(contentsOf: parseInventoryFile(at: url))
        }
        return events
    }

    private func isTrashInventoryFile(_ url: URL) -> Bool {
        ["trash_inventory.json", "trash_export.json", "trash_export.jsonl"].contains(url.lastPathComponent)
    }

    private func residualTrashEvents(root: ArtifactRoot, inventoriedNames: Set<String>, seen: inout PathDeduper) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        for url in root.enumerate(matching: isResidualTrashFile) {
            guard !inventoriedNames.contains(url.lastPathComponent) else { continue }
            let key = "trash-file:" + relativePath(of: url, under: root)
            if seen.insert(pathKey: key), let event = makeFromTrashFile(url: url, root: root) { events.append(event) }
        }
        return events
    }

    private func isResidualTrashFile(_ url: URL) -> Bool {
        let path = url.path.lowercased()
        guard path.contains("/.trash/") || path.contains("/.trashes/") else { return false }
        guard isRegularTrashFile(url) else { return false }
        return !isTrashInventoryFile(url) && !url.lastPathComponent.hasSuffix(".jsonl") && !url.lastPathComponent.hasSuffix(".json")
    }

    private func isRegularTrashFile(_ url: URL) -> Bool {
        var isDirectory: ObjCBool = false
        return FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory) && !isDirectory.boolValue
    }

    private func parseInventoryFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" || url.lastPathComponent.hasSuffix(".jsonl") {
            return ArtifactIO.jsonlDictionaries(contentsOf: url).compactMap { makeEvent(from: $0, sourceURL: url) }
        }
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }

        let entries = ArtifactIO.dictionaryEntries(
            from: obj,
            nestedKeys: ["items", "trash", "entries"],
            identityKeys: ["filename", "original_path"]
        )
        return entries.compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeFromTrashFile(url: URL, root: ArtifactRoot) -> EventEnvelope? {
        let filename = url.lastPathComponent
        // Image-relative path under ArtifactRoot (never host-absolute /Users/<dev>/…)
        let trashPath = relativePath(of: url, under: root)
        return makeEvent(
            from: [
                "filename": filename,
                "trash_path": trashPath,
                "original_path": "",
            ],
            sourceURL: url,
            imageRoot: root
        )
    }

    private struct TrashDetails {
        let filename: String
        let original: String
        let trashPath: String
        let deletedAt: String
        let risk: [String]
    }

    private func makeEvent(
        from item: [String: Any],
        sourceURL: URL,
        imageRoot: ArtifactRoot? = nil
    ) -> EventEnvelope? {
        guard let details = trashDetails(item: item, sourceURL: sourceURL, imageRoot: imageRoot) else { return nil }
        let fields = trashFields(item: item, details: details, sourceURL: sourceURL)
        let refs = trashReferences(filename: details.filename, original: details.original, trashPath: details.trashPath)
        return trashEnvelope(item: item, sourceURL: sourceURL, details: details, fields: fields, references: refs)
    }

    private func trashDetails(item: [String: Any], sourceURL: URL, imageRoot: ArtifactRoot?) -> TrashDetails? {
        let filename = stringish(item["filename"]) ?? stringish(item["name"]) ?? stringish(item["item"]) ?? ""
        let original = stringish(item["original_path"]) ?? stringish(item["originalPath"]) ?? stringish(item["where_from"]) ?? ""
        let trashPath = normalizedTrashPath(item: item, sourceURL: sourceURL, imageRoot: imageRoot)
        guard !filename.isEmpty || !original.isEmpty || trashPath.lowercased().contains(".trash") else { return nil }
        let deletedAt = stringish(item["deleted_at"]) ?? stringish(item["deletion_date"]) ?? stringish(item["timestamp"]) ?? ""
        return TrashDetails(filename: filename, original: original, trashPath: trashPath, deletedAt: deletedAt, risk: trashRiskTags(item: item, filename: filename, original: original))
    }

    private func normalizedTrashPath(item: [String: Any], sourceURL: URL, imageRoot: ArtifactRoot?) -> String {
        let path = stringish(item["trash_path"]) ?? stringish(item["path"]) ?? ""
        if !path.isEmpty { return imageRelativePath(path) }
        if let imageRoot { return relativePath(of: sourceURL, under: imageRoot) }
        return imageRelativePath(ArtifactRoot.pathKey(sourceURL))
    }

    private func trashEnvelope(item: [String: Any], sourceURL: URL, details: TrashDetails, fields: [String: String], references: [EntityID]) -> EventEnvelope {
        EventEnvelope(identity: EventEnvelope.Identity(kind: "filesystem.trash", label: "TRASH"), capture: EventEnvelope.Capture(source: .parser, eventTime: parseDate(item["deleted_at"] ?? item["deletion_date"] ?? item["timestamp"]) ?? Date(timeIntervalSince1970: 0), collectedAt: Date()), payload: EventEnvelope.Payload(entityRefs: references, properties: fields, provenance: ArtifactRoot.pathKey(sourceURL), confidence: 0.9))
    }

    private func trashRiskTags(item: [String: Any], filename: String, original: String) -> [String] {
        var tags = (stringish(item["risk_tags"]) ?? "")
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
        let name = filename.lowercased()
        let origin = original.lowercased()
        if hasCredentialMarker(name: name, origin: origin) {
            appendRiskTags(["credential_material", "sensitive_path"], to: &tags)
        }
        if hasSuspiciousMarker(name: name, origin: origin) {
            appendRiskTags(["suspicious_name"], to: &tags)
        }
        if hasTransientOrigin(origin) {
            appendRiskTags(["tmp_origin"], to: &tags)
        }
        if isExecutable(item: item, name: name) {
            appendRiskTags(["executable"], to: &tags)
        }
        return tags
    }

    private func hasCredentialMarker(name: String, origin: String) -> Bool {
        ["id_rsa", "password", "credential", "secret"].contains(where: name.contains) || name.hasSuffix(".pem") || origin.contains(".ssh/")
    }

    private func hasSuspiciousMarker(name: String, origin: String) -> Bool {
        ["evil", "payload", "implant"].contains(where: name.contains) || origin.contains("evil")
    }

    private func hasTransientOrigin(_ origin: String) -> Bool {
        ["/tmp/", "/downloads/"].contains(where: origin.contains)
    }

    private func isExecutable(item: [String: Any], name: String) -> Bool {
        boolish(item["executable"]) == true || (!name.contains(".") && ["agent", "implant", "payload"].contains(where: name.contains))
    }

    private func appendRiskTags(_ additions: [String], to tags: inout [String]) {
        for tag in additions where !tags.contains(tag) {
            tags.append(tag)
        }
    }

    private func trashFields(item: [String: Any], details: TrashDetails, sourceURL: URL) -> [String: String] {
        var fields = [
            "trash.filename": details.filename, "trash.original_path": details.original,
            "trash.trash_path": details.trashPath, "trash.deleted_at": details.deletedAt,
            FieldTaxonomy.eventType: "filesystem.trash",
        ]
        if !details.risk.isEmpty { fields["trash.risk_tags"] = details.risk.joined(separator: ",") }
        if let size = stringish(item["size_bytes"]) ?? stringish(item["size"]) { fields["trash.size_bytes"] = size }
        if let user = inferUser(from: details.trashPath.isEmpty ? details.original : details.trashPath)
            ?? inferUser(from: details.original) ?? inferUser(from: ArtifactRoot.pathKey(sourceURL)) {
            fields[FieldTaxonomy.userName] = user
        }
        return fields
    }

    private func trashReferences(filename: String, original: String, trashPath: String) -> [EntityID] {
        var references = [EntityID(kind: .host, value: "trash|\(filename)")]
        if !original.isEmpty { references.insert(.file(path: original), at: 0) }
        if !trashPath.isEmpty { references.insert(.file(path: trashPath), at: original.isEmpty ? 0 : 1) }
        return references
    }

    /// Path relative to the artifact image root (POSIX separators).
    private func relativePath(of url: URL, under root: ArtifactRoot) -> String {
        let abs = ArtifactRoot.pathKey(url)
        let rootPath = ArtifactRoot.pathKey(root.root)
        if abs == rootPath { return "" }
        if abs.hasPrefix(rootPath + "/") {
            return String(abs.dropFirst(rootPath.count + 1))
        }
        return imageRelativePath(abs)
    }

    /// Strip host prefix before the image's own `Users/` segment when present.
    private func imageRelativePath(_ path: String) -> String {
        let parts = path.split(separator: "/").map(String.init)
        if let idx = parts.lastIndex(of: "Users"), idx + 1 < parts.count {
            return parts[idx...].joined(separator: "/")
        }
        // Prefer paths that already look image-relative
        if path.hasPrefix("Users/") || path.hasPrefix("Library/") || path.hasPrefix("var/") {
            return path
        }
        return path
    }
}
