import Foundation
import RootstockBlueCore

/// Shell initialization / profile files - persistence & environment hijack surface.
///
/// Complements `TerminalParser` (command history) with init-time execution
/// (`.zshrc`, `.bash_profile`, `/etc/profile`, …). High-ROI LotL path (T1546.004):
/// PATH prepend, aliases, `DYLD_INSERT_LIBRARIES`, `curl|sh` in profiles.
///
/// Emits stable `persistence.*` fields, entity IDs, and heuristic risk tags for
/// fixture-backed detections.
public struct ShellProfilesParser: ArtifactParser {
    private struct ProfileContext {
        let url: URL
        let path: String
        let scope: String
        let user: String
    }

    private struct ProfileLine {
        let context: ProfileContext
        let text: String
        let number: Int
        let risks: [String]
    }

    public let manifest = PluginManifest(
        id: "SHELLPROFILES",
        tier: .tier1,
        description: "Shell init profiles (.zshrc, .bash_profile, /etc/profile, …)"
    )

    public init() {}

    private static let profileNames: Set<String> = [
        ".zshrc", ".zprofile", ".zshenv", ".zlogin", ".zlogout",
        ".bashrc", ".bash_profile", ".bash_login", ".bash_logout",
        ".profile",
        "zshrc", "zprofile", "zshenv", "bashrc", "profile",
    ]

    private static let systemRelatives = [
        "etc/profile", "private/etc/profile",
        "etc/zshrc", "private/etc/zshrc",
        "etc/zprofile", "private/etc/zprofile",
        "etc/bashrc", "private/etc/bashrc",
        "etc/zshenv", "private/etc/zshenv",
    ]

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var seen = PathDeduper()
        return systemProfileEvents(root, seen: &seen) + discoveredProfileEvents(root, seen: &seen)
    }

    private func systemProfileEvents(_ root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        for rel in Self.systemRelatives {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseProfile(at: url, scope: "system", user: "root"))
                }
            }
        }
        return events
    }

    private func discoveredProfileEvents(_ root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        for url in root.enumerate(matching: isProfileFile) {
            if !seen.insert(url) { continue }
            let user = profileUser(url)
            let scope = profileScope(url, user: user)
            events.append(contentsOf: parseProfile(at: url, scope: scope, user: user))
        }
        return events
    }

    private func isProfileFile(_ url: URL) -> Bool {
        let name = url.lastPathComponent
        return Self.profileNames.contains(name) || (url.path.contains("/profile.d/") && (name.hasSuffix(".sh") || name.hasSuffix(".zsh")))
    }

    private func profileUser(_ url: URL) -> String { inferUser(from: url) ?? (url.path.contains("/etc/") ? "root" : "unknown") }
    private func profileScope(_ url: URL, user: String) -> String { user == "root" || url.path.contains("/etc/") ? "system" : "user" }

    private func parseProfile(at url: URL, scope: String, user: String) -> [EventEnvelope] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        let pathKey = ArtifactRoot.pathKey(url)
        let context = ProfileContext(url: url, path: pathKey, scope: scope, user: user)
        let events = text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline).enumerated().compactMap {
            lineEvent(String($0.element), lineNumber: $0.offset + 1, context: context)
        }
        return events.isEmpty ? [emptyProfileEvent(context)] : events
    }

    private func lineEvent(_ raw: String, lineNumber: Int, context: ProfileContext) -> EventEnvelope? {
        let line = raw.trimmingCharacters(in: .whitespaces)
        guard !line.isEmpty, !line.hasPrefix("#") else { return nil }
        let risks = riskTags(for: line)
        let profileLine = ProfileLine(context: context, text: line, number: lineNumber, risks: risks)
        let program = absoluteProgram(in: line)
        var fields = profileFields(profileLine)
        if let program { fields[FieldTaxonomy.processPath] = program; fields["persistence.program"] = program }
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "persistence.item",
                label: "SHELLPROFILES"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: fileMTime(context.url),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: profileEntities(profileLine, program: program),
                properties: fields,
                provenance: context.path,
                confidence: risks.isEmpty ? 0.9 : 0.96
            )
        )
    }

    private func absoluteProgram(in line: String) -> String? { line.split(whereSeparator: { $0 == " " || $0 == "\t" || $0 == "|" || $0 == ";" }).map(String.init).first { $0.hasPrefix("/") } }
    private func profileFields(_ line: ProfileLine) -> [String: String] { var fields = ["persistence.kind":"shell_profile", "persistence.path":line.context.path, "persistence.command":line.text, "persistence.line":String(line.number), "shell.profile_scope":line.context.scope, FieldTaxonomy.filePath:line.context.path, FieldTaxonomy.eventType:"persistence.item", FieldTaxonomy.userName:line.context.user]; if !line.risks.isEmpty { fields["persistence.risk_tags"] = line.risks.joined(separator:","); fields["shell.risk"] = line.risks.joined(separator:",") }; return fields }
    private func profileEntities(_ line: ProfileLine, program: String?) -> [EntityID] { var entities:[EntityID] = [EntityID(kind:.persistence,value:"shell_profile|\(line.context.path)|\(line.number)"),.file(path:line.context.path),.user(name:line.context.user)]; if let program { entities.append(.file(path:program)) }; return entities }
    private func emptyProfileEvent(_ context: ProfileContext) -> EventEnvelope { EventEnvelope(
        identity: EventEnvelope.Identity(
            kind: "persistence.item",
            label: "SHELLPROFILES"
        ),
        capture: EventEnvelope.Capture(
            source: .parser,
            eventTime: fileMTime(context.url),
            collectedAt: Date()
        ),
        payload: EventEnvelope.Payload(
            entityRefs: [EntityID(kind:.persistence,value:"shell_profile|\(context.path)"),.file(path:context.path),.user(name:context.user)],
            properties: ["persistence.kind":"shell_profile","persistence.path":context.path,"persistence.command":"(empty or comments only)","shell.profile_scope":context.scope,"shell.profile_name":context.url.lastPathComponent,FieldTaxonomy.filePath:context.path,FieldTaxonomy.eventType:"persistence.item",FieldTaxonomy.userName:context.user],
            provenance: context.path,
            confidence: 0.75
        )
    ) }

    /// Heuristic risk tags for blue-team triage (not a full sandbox).
    private func riskTags(for line: String) -> [String] {
        let lower = line.lowercased()
        return dyldRisk(lower) + curlRisk(lower) + wgetRisk(lower) + temporaryRisk(lower) + base64Risk(lower) + evalRisk(lower) + pathRisk(lower) + aliasRisk(lower)
    }

    private func dyldRisk(_ line: String) -> [String] { line.contains("dyld_insert_libraries") ? ["dyld_insert"] : [] }
    private func curlRisk(_ line: String) -> [String] { line.contains("curl") && shellPipe(line) ? ["curl_pipe_shell"] : [] }
    private func wgetRisk(_ line: String) -> [String] { line.contains("wget") && shellPipe(line) ? ["wget_pipe_shell"] : [] }
    private func temporaryRisk(_ line: String) -> [String] { line.contains("/tmp/") || line.contains("/var/tmp/") || line.contains("/dev/shm") ? ["tmp_path"] : [] }
    private func base64Risk(_ line: String) -> [String] { line.contains("base64") && (line.contains("-d") || line.contains("decode")) ? ["base64_decode"] : [] }
    private func evalRisk(_ line: String) -> [String] { line.hasPrefix("eval ") || line.contains("$(curl") || line.contains("`curl") ? ["eval_remote"] : [] }
    private func pathRisk(_ line: String) -> [String] { line.contains("export path=") || line.hasPrefix("path=") ? ["path_override"] : [] }
    private func aliasRisk(_ line: String) -> [String] { line.contains("alias ") && (line.contains("sudo=") || line.contains("ssh=")) ? ["alias_hijack"] : [] }
    private func shellPipe(_ line: String) -> Bool { line.contains("|sh") || line.contains("| bash") || line.contains("|bash") }

    private func fileMTime(_ url: URL) -> Date {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)
    }
}
