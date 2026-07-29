import Foundation
import RootstockBlueCore

/// Cron, at(1) tabs, and periodic jobs - classic Unix persistence on macOS.
///
/// Does not own LaunchAgents/LaunchDaemons (see AutostartParser).
public struct CronParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "CRON",
        tier: .tier1,
        description: "crontab, at tabs, and periodic jobs"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var seen = PathDeduper()
        return systemCrontabs(root, seen: &seen)
            + discoveredTabs(root, seen: &seen)
            + explicitAtTabs(root, seen: &seen)
            + periodicScripts(root, seen: &seen)
    }

    private func systemCrontabs(_ root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        ["etc/crontab", "private/etc/crontab"].compactMap { root.firstExisting([$0]) }
            .flatMap { seen.insert($0) ? parseCrontab(at: $0, kind: "cron", defaultUser: "root") : [] }
    }

    private func discoveredTabs(_ root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        root.enumerate(matching: Self.isCronTab).filter { seen.insert($0) }.flatMap { url in
            let isAt = url.path.contains("/at/tabs/")
            return parseCrontab(at: url, kind: isAt ? "at" : "cron", defaultUser: isAt ? url.lastPathComponent : cronUser(from: url) ?? "root")
        }
    }

    private func explicitAtTabs(_ root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        ["private/var/at/tabs", "var/at/tabs"].flatMap { base in
            let directory = root.file(base)
            let items = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles])) ?? []
            return items.flatMap { seen.insert($0) ? parseCrontab(at: $0, kind: "at", defaultUser: $0.lastPathComponent) : [] }
        }
    }

    private func periodicScripts(_ root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        root.enumerate(matching: Self.isPeriodicScript).compactMap { seen.insert($0) ? parsePeriodic(at: $0) : nil }
    }

    private static func isCronTab(_ url: URL) -> Bool {
        let path = url.path
        let name = url.lastPathComponent
        return path.contains("/cron.d/") || path.hasSuffix("/cron.d/\(name)") || name == ".cron" || path.hasSuffix("/.cron") || path.contains("/cron/tabs/") || path.contains("/at/tabs/")
    }

    private static func isPeriodicScript(_ url: URL) -> Bool {
        url.path.contains("/periodic/") && !url.hasDirectoryPath && !url.lastPathComponent.hasPrefix(".")
    }

    // MARK: - crontab / at

    private func parseCrontab(at url: URL, kind: String, defaultUser: String) -> [EventEnvelope] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        return text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline).enumerated().compactMap {
            eventForLine(String($0.element), number: $0.offset + 1, kind: kind, defaultUser: defaultUser, sourceURL: url)
        }
    }

    private func eventForLine(_ rawLine: String, number: Int, kind: String, defaultUser: String, sourceURL: URL) -> EventEnvelope? {
        let line = rawLine.trimmingCharacters(in: .whitespaces)
        guard !isIgnoredCronLine(line) else { return nil }
        let entry = kind == "at"
            ? CronEntry(schedule: "at", user: defaultUser, command: line, kind: "at")
            : parseCronLine(line, defaultUser: defaultUser)
        return entry.flatMap { makePersistenceEvent($0, sourceURL: sourceURL, lineNo: number) }
    }

    private func isIgnoredCronLine(_ line: String) -> Bool {
        let environmentPrefix = ["SHELL=", "PATH=", "MAILTO=", "HOME=", "LOGNAME="]
        let assignment = line.contains("=") && !line.contains(" ") && line.split(separator: "=", maxSplits: 1).first.map { !$0.contains("/") } == true
        return line.isEmpty || line.hasPrefix("#") || assignment || environmentPrefix.contains(where: line.hasPrefix)
    }

    /// Vixie cron special schedule strings (must be handled before 5-field path).
    private static let vixieSpecials: Set<String> = [
        "@reboot", "@yearly", "@annually", "@monthly",
        "@weekly", "@daily", "@midnight", "@hourly",
    ]

    /// Parse classic crontab line: Vixie specials (`@reboot`…), user crontab (5 fields + cmd),
    /// or system/cron.d (6: schedule + user + cmd).
    private func parseCronLine(_ line: String, defaultUser: String) -> CronEntry? {
        let tokens = tokenizeCron(line)
        guard !tokens.isEmpty else { return nil }
        return tokens[0].hasPrefix("@")
            ? parseVixieEntry(tokens, defaultUser: defaultUser)
            : parseClassicEntry(tokens, defaultUser: defaultUser)
    }

    private func parseVixieEntry(_ tokens: [String], defaultUser: String) -> CronEntry? {
        let head = tokens[0].lowercased()
        guard Self.vixieSpecials.contains(head) else { return nil }
        let rest = Array(tokens.dropFirst())
        guard !rest.isEmpty else { return nil }
        let hasExplicitUser = isUserToken(rest[0]) && rest.count >= 2
        let user = hasExplicitUser ? rest[0] : defaultUser
        let command = hasExplicitUser ? rest.dropFirst().joined(separator: " ") : rest.joined(separator: " ")
        return CronEntry(schedule: head, user: user, command: command)
    }

    private func parseClassicEntry(_ tokens: [String], defaultUser: String) -> CronEntry? {
        guard tokens.count >= 6 else { return nil }
        let scheduleFields = Array(tokens.prefix(5))
        let rest = Array(tokens.dropFirst(5))
        guard !rest.isEmpty else { return nil }
        let schedule = scheduleFields.joined(separator: " ")
        let hasExplicitUser = isUserToken(rest[0]) && rest.count >= 2
        let user = hasExplicitUser ? rest[0] : defaultUser
        let command = hasExplicitUser ? rest.dropFirst().joined(separator: " ") : rest.joined(separator: " ")
        return CronEntry(schedule: schedule, user: user, command: command)
    }

    private func isUserToken(_ token: String) -> Bool {
        !token.contains("/") && !token.contains("$") && !token.contains("=")
            && token.rangeOfCharacter(from: .letters) != nil && token.count < 32
    }

    private func tokenizeCron(_ line: String) -> [String] {
        // Split on whitespace but keep command intact by joining after schedule fields.
        line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
    }

    // MARK: - periodic

    private func parsePeriodic(at url: URL) -> EventEnvelope? {
        let path = ArtifactRoot.pathKey(url)
        let schedule: String
        if path.contains("/daily/") {
            schedule = "daily"
        } else if path.contains("/weekly/") {
            schedule = "weekly"
        } else if path.contains("/monthly/") {
            schedule = "monthly"
        } else {
            schedule = "periodic"
        }

        // Prefer shebang / first non-comment line as command summary; fall back to path.
        var command = path
        if let text = try? String(contentsOf: url, encoding: .utf8) {
            for raw in text.split(whereSeparator: \.isNewline) {
                let line = String(raw).trimmingCharacters(in: .whitespaces)
                if line.isEmpty || line.hasPrefix("#") { continue }
                command = line
                break
            }
        }

        return makePersistenceEvent(
            CronEntry(schedule: schedule, user: "root", command: command, kind: "periodic"),
            sourceURL: url,
            lineNo: 0
        )
    }

    // MARK: - event

    private func makePersistenceEvent(_ entry: CronEntry, sourceURL: URL, lineNo: Int) -> EventEnvelope? {
        let trimmed = entry.command.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return nil }

        var fields: [String: String] = [
            "persistence.kind": entry.kind,
            "persistence.schedule": entry.schedule,
            "persistence.command": trimmed,
            "persistence.path": ArtifactRoot.pathKey(sourceURL),
            FieldTaxonomy.filePath: ArtifactRoot.pathKey(sourceURL),
            FieldTaxonomy.eventType: "persistence.item",
            FieldTaxonomy.userName: entry.user,
        ]
        if lineNo > 0 {
            fields["persistence.line"] = String(lineNo)
        }
        // First token as process path when absolute
        let first = trimmed.split(whereSeparator: { $0 == " " || $0 == "\t" }).first.map(String.init) ?? ""
        if first.hasPrefix("/") {
            fields[FieldTaxonomy.processPath] = first
            fields["persistence.program"] = first
        }

        var entities: [EntityID] = [
            EntityID(kind: .persistence, value: "\(entry.kind)|\(entry.schedule)|\(trimmed)"),
            .file(path: ArtifactRoot.pathKey(sourceURL)),
            .user(name: entry.user),
        ]
        if first.hasPrefix("/") {
            entities.append(.file(path: first))
        }

        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "persistence.item",
                label: "CRON"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: fileMTime(sourceURL),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: entities,
                properties: fields,
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: entry.kind == "periodic" ? 0.92 : 0.96
            )
        )
    }

    private struct CronEntry {
        let schedule: String
        let user: String
        let command: String
        let kind: String

        init(schedule: String, user: String, command: String, kind: String = "cron") {
            self.schedule = schedule
            self.user = user
            self.command = command
            self.kind = kind
        }
    }

    private func cronUser(from url: URL) -> String? {
        if let user = inferUser(from: url) { return user }
        // cron.d filename sometimes is username
        let base = url.lastPathComponent
        if base != "crontab" && !base.contains(".") && base.rangeOfCharacter(from: .letters) != nil {
            return base
        }
        return nil
    }

    private func fileMTime(_ url: URL) -> Date {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)
    }
}
