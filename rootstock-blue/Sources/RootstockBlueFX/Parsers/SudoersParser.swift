import Foundation
import RootstockBlueCore

/// sudoers policy surface - privilege escalation & persistence-adjacent access control.
///
/// Offline parse of `/etc/sudoers` and `/etc/sudoers.d/*` (and private/etc variants).
/// Emits structured `privilege.sudoers` events with risk tags (NOPASSWD, ALL=(ALL), !authenticate).
///
/// Emits normalized fields, entity IDs, and fixture-backed detections for
/// dangerous grants. It does not implement a complete sudo policy engine.
public struct SudoersParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "SUDOERS",
        tier: .tier1,
        description: "sudoers and sudoers.d privilege policy entries"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var seen = PathDeduper()
        var events = parseNamedSudoersFiles(root: root, seen: &seen)
        events.append(contentsOf: parseSudoersDirectories(root: root, seen: &seen))
        events.append(contentsOf: parseEnumeratedSudoersFiles(root: root, seen: &seen))
        return events
    }

    private func parseNamedSudoersFiles(root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        for path in ["etc/sudoers", "private/etc/sudoers"] {
            guard let url = root.firstExisting([path]), seen.insert(url) else { continue }
            events.append(contentsOf: parseSudoersFile(at: url))
        }
        return events
    }

    private func parseSudoersDirectories(root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        for path in ["etc/sudoers.d", "private/etc/sudoers.d"] {
            let directory = root.file(path)
            guard let items = try? FileManager.default.contentsOfDirectory(
                at: directory,
                includingPropertiesForKeys: [.isRegularFileKey],
                options: [.skipsHiddenFiles]
            ) else { continue }
            for item in items where seen.insert(item) && isSudoersInclude(item) {
                events.append(contentsOf: parseSudoersFile(at: item))
            }
        }
        return events
    }

    private func isSudoersInclude(_ url: URL) -> Bool {
        let name = url.lastPathComponent
        return !name.hasSuffix("~") && !name.hasPrefix(".")
    }

    private func parseEnumeratedSudoersFiles(root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        for url in root.enumerate(matching: isSudoersIncludePath) where seen.insert(url) {
            events.append(contentsOf: parseSudoersFile(at: url))
        }
        return events
    }

    private func isSudoersIncludePath(_ url: URL) -> Bool {
        url.path.contains("/sudoers.d/") && !url.hasDirectoryPath
    }

    private func parseSudoersFile(at url: URL) -> [EventEnvelope] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        let path = ArtifactRoot.pathKey(url)
        return text
            .split(omittingEmptySubsequences: false, whereSeparator: \.isNewline)
            .enumerated()
            .compactMap { index, rawLine in
                sudoersEvent(from: rawLine, lineNumber: index + 1, path: path, sourceURL: url)
            }
    }

    private func sudoersEvent(
        from rawLine: Substring,
        lineNumber: Int,
        path: String,
        sourceURL: URL
    ) -> EventEnvelope? {
        let line = normalizedSudoersLine(rawLine)
        guard !line.isEmpty, !line.hasPrefix("#") else { return nil }

        let kind = sudoersEntryKind(line)
        let risk = riskTags(for: line)
        let fields = sudoersFields(line: line, kind: kind, lineNumber: lineNumber, path: path, risk: risk)
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "privilege.sudoers",
                label: "SUDOERS"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: fileMTime(sourceURL),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: sudoersEntities(path: path, lineNumber: lineNumber, fields: fields),
                properties: fields,
                provenance: path,
                confidence: risk.isEmpty ? 0.9 : 0.97
            )
        )
    }

    private func normalizedSudoersLine(_ rawLine: Substring) -> String {
        var line = String(rawLine).trimmingCharacters(in: .whitespaces)
        while line.hasSuffix("\\") {
            line = String(line.dropLast()).trimmingCharacters(in: .whitespaces)
        }
        return line
    }

    private func sudoersEntryKind(_ line: String) -> String {
        if line.hasPrefix("Defaults") { return "defaults" }
        if ["User_Alias", "Runas_Alias", "Host_Alias", "Cmnd_Alias"].contains(where: line.hasPrefix) {
            return "alias"
        }
        return line.hasPrefix("@") ? "include" : "rule"
    }

    private func sudoersFields(
        line: String,
        kind: String,
        lineNumber: Int,
        path: String,
        risk: [String]
    ) -> [String: String] {
        var fields: [String: String] = [
            "privilege.kind": kind,
            "privilege.line": line,
            "privilege.path": path,
            "privilege.line_no": String(lineNumber),
            "sudoers.entry": line,
            FieldTaxonomy.filePath: path,
            FieldTaxonomy.eventType: "privilege.sudoers",
        ]
        if !risk.isEmpty {
            let value = risk.joined(separator: ",")
            fields["privilege.risk_tags"] = value
            fields["sudoers.risk"] = value
        }
        if kind == "rule", let user = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).first {
            fields[FieldTaxonomy.userName] = String(user)
            fields["sudoers.user"] = String(user)
        }
        return fields
    }

    private func sudoersEntities(path: String, lineNumber: Int, fields: [String: String]) -> [EntityID] {
        var entities: [EntityID] = [
            EntityID(kind: .auth, value: "sudoers|\(path)|\(lineNumber)"),
            .file(path: path),
        ]
        if let user = fields[FieldTaxonomy.userName] {
            entities.append(.user(name: user))
        }
        return entities
    }

    private func riskTags(for line: String) -> [String] {
        let upper = line.uppercased()
        var tags: [String] = []
        if upper.contains("NOPASSWD") { tags.append("nopasswd") }
        if containsNoAuthenticate(upper) { tags.append("no_authenticate") }
        if containsAllRunAs(upper) { tags.append("all_runas") }
        if containsBroadGrant(upper) { tags.append("broad_grant") }
        if containsTemporaryCommand(upper) { tags.append("tmp_command") }
        if upper.contains("!REQUIRETTY") { tags.append("no_requiretty") }
        return tags
    }

    private func containsNoAuthenticate(_ line: String) -> Bool {
        line.contains("!AUTHENTICATE") || line.contains("! AUTHENTICATE")
    }

    private func containsAllRunAs(_ line: String) -> Bool {
        line.contains("ALL=(ALL)") || line.contains("ALL = (ALL)")
    }

    private func containsBroadGrant(_ line: String) -> Bool {
        guard line.contains("ALL") else { return false }
        let hasBroadTarget = line.contains("ALL:ALL") || line.hasSuffix("ALL") || line.contains(" ALL")
        return hasBroadTarget && (line.contains("(ALL)") || line.contains("ALL:ALL"))
    }

    private func containsTemporaryCommand(_ line: String) -> Bool {
        line.contains("/TMP/") || line.contains("/VAR/TMP/")
    }

    private func fileMTime(_ url: URL) -> Date {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)
    }
}
