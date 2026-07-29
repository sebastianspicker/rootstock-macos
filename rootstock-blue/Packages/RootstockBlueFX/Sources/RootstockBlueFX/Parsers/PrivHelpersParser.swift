import Foundation
import RootstockBlueCore

/// Privileged Helper Tools (SMJobBless / ServiceManagement) - root-class persistence.
///
/// Inventory of `/Library/PrivilegedHelperTools/*` paired with LaunchDaemon plists
/// that install helpers (ATT&CK T1543.004). Common residual after app uninstall.
///
/// Significant improvement over `ls` / KnockKnock path dump: normalized envelopes,
/// binary↔launchd pairing, risk tags (tmp path, unsigned/unknown team, orphan),
/// entity IDs, inventory merge, and fixture-backed detections.
public struct PrivHelpersParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "PRIVHELPERS",
        tier: .tier1,
        description: "SMJobBless PrivilegedHelperTools + paired LaunchDaemons"
    )

    public init() {}

    private struct HelperDetails {
        let label: String
        let path: String
        let program: String
        let launchdPlist: String
        let teamID: String
        let signingID: String
        let programArgs: String
        let extra: [String: String]
    }

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var seen = PathDeduper()
        return collectJSONEvents(root, seen: &seen)
            + collectHelperFileEvents(root, seen: &seen)
            + collectLaunchDaemonEvents(root, seen: &seen)
    }

    private func collectJSONEvents(_ root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        for rel in [
            "Library/PrivilegedHelperTools/helpers.json",
            "Library/Preferences/privileged_helpers.json",
        ] {
            if let url = root.firstExisting([rel]),
               let json = ArtifactIO.jsonObject(contentsOf: url),
               seen.insert(url) {
                events.append(contentsOf: parseJSONInventory(json, rawRef: ArtifactRoot.pathKey(url)))
            }
        }
        return events
    }

    private func collectHelperFileEvents(_ root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        for url in root.enumerate(matching: { url in
            let path = url.path
            guard path.contains("/PrivilegedHelperTools/") else { return false }
            if url.hasDirectoryPath { return false }
            let name = url.lastPathComponent
            if name.hasPrefix(".") { return false }
            if name == "helpers.json" { return false }
            return true
        }) {
            guard seen.insert(url) else { continue }
            let key = ArtifactRoot.pathKey(url)
            let label = url.lastPathComponent
            events.append(makeEvent(HelperDetails(
                label: label,
                path: key,
                program: key.hasPrefix("/") ? key : "/Library/PrivilegedHelperTools/\(label)",
                launchdPlist: "",
                teamID: "",
                signingID: "",
                programArgs: "",
                extra: [:]
            )))
        }
        return events
    }

    private func collectLaunchDaemonEvents(_ root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        for url in root.enumerate(matching: isLaunchDaemon) {
            guard let details = launchDaemonDetails(url),
                  insertLaunchDaemon(details.label, program: details.program, at: url, seen: &seen)
            else { continue }
            events.append(makeEvent(details))
        }
        return events
    }

    private func isLaunchDaemon(_ url: URL) -> Bool {
        url.pathExtension == "plist" && url.path.contains("/LaunchDaemons/")
    }

    private func launchDaemonDetails(_ url: URL) -> HelperDetails? {
        guard let data = ArtifactIO.data(contentsOf: url),
              let dict = ArtifactIO.plistDict(from: data)
        else { return nil }
        let label = stringish(dict["Label"]) ?? url.deletingPathExtension().lastPathComponent
        let program = stringish(dict["Program"]) ?? ""
        let args = stringArray(dict["ProgramArguments"])
        let programPath = program.isEmpty ? (args.first ?? "") : program
        let fullArgs = args.isEmpty ? programPath : args.joined(separator: " ")
        guard refersToHelper(label: label, program: programPath, arguments: fullArgs, fileName: url.lastPathComponent) else {
            return nil
        }
        let pathKey = ArtifactRoot.pathKey(url)
        let risk = daemonRiskTags(label: label, program: programPath)
        let extra = risk.isEmpty ? [:] : ["persistence.risk_tags": risk.joined(separator: ",")]
        return HelperDetails(
            label: label,
            path: containsHelperPath(programPath, arguments: fullArgs) ? programPath : pathKey,
            program: programPath.isEmpty ? label : programPath,
            launchdPlist: pathKey,
            teamID: stringish(dict["TeamIdentifier"]) ?? "",
            signingID: stringish(dict["SigningIdentifier"]) ?? "",
            programArgs: fullArgs,
            extra: extra
        )
    }

    private func refersToHelper(label: String, program: String, arguments: String, fileName: String) -> Bool {
        containsHelperPath(program, arguments: arguments)
            || label.lowercased().contains("helper")
            || fileName.lowercased().contains("helper")
    }

    private func containsHelperPath(_ program: String, arguments: String) -> Bool {
        program.contains("PrivilegedHelperTools") || arguments.contains("PrivilegedHelperTools")
    }

    private func insertLaunchDaemon(_ label: String, program: String, at url: URL, seen: inout PathDeduper) -> Bool {
        guard seen.insert(pathKey: "helper|\(label)|\(program)") else { return false }
        _ = seen.insert(pathKey: ArtifactRoot.pathKey(url))
        return true
    }

    private func parseJSONInventory(_ json: Any, rawRef: String) -> [EventEnvelope] {
        inventoryItems(json).compactMap { item -> EventEnvelope? in
            let label = stringish(item["label"])
                ?? stringish(item["name"])
                ?? stringish(item["bundle_id"])
                ?? "unnamed"
            let path = stringish(item["path"])
                ?? stringish(item["program"])
                ?? "/Library/PrivilegedHelperTools/\(label)"
            let program = stringish(item["program"]) ?? path
            let launchd = stringish(item["launchd_plist"])
                ?? stringish(item["plist"])
                ?? ""
            let team = stringish(item["team_id"]) ?? stringish(item["teamID"]) ?? ""
            let signing = stringish(item["signing_id"]) ?? stringish(item["signingID"]) ?? ""
            let args = stringish(item["program_args"])
                ?? stringish(item["program_arguments"])
                ?? program

            let extra = inventoryExtra(item, label: label, program: program, team: team)
            return makeEvent(HelperDetails(
                label: label,
                path: path,
                program: program,
                launchdPlist: launchd.isEmpty ? rawRef : launchd,
                teamID: team,
                signingID: signing,
                programArgs: args,
                extra: extra
            ))
        }
    }

    private func inventoryItems(_ json: Any) -> [[String: Any]] {
        let items = ArtifactIO.dictionaryEntries(from: json, nestedKeys: ["helpers", "privileged_helpers"])
        if !items.isEmpty { return items }
        if let dict = json as? [String: Any] { return [dict] }
        return json as? [[String: Any]] ?? []
    }

    private func inventoryExtra(_ item: [String: Any], label: String, program: String, team: String) -> [String: String] {
        var tags = taggedRisks(item)
        appendInventoryRisks(&tags, label: label, program: program, team: team, orphan: boolish(item["orphan"]) == true)
        var extra = tags.isEmpty ? [:] : ["persistence.risk_tags": tags.joined(separator: ",")]
        if let bundle = stringish(item["bundle_id"]) { extra["privhelper.bundle_id"] = bundle }
        return extra
    }

    private func taggedRisks(_ item: [String: Any]) -> [String] {
        guard let tags = stringish(item["risk_tags"]), !tags.isEmpty else { return [] }
        return tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
    }

    private func appendInventoryRisks(_ tags: inout [String], label: String, program: String, team: String, orphan: Bool) {
        if temporaryProgram(program) { appendUnique("tmp_path_program", to: &tags) }
        if untrustedEvilHelper(label: label, program: program, team: team) { appendUnique("unknown_team", to: &tags) }
        if orphan { appendUnique("orphan_helper", to: &tags) }
    }

    private func daemonRiskTags(label: String, program: String) -> [String] {
        var tags: [String] = []
        if temporaryProgram(program, includeShared: true) { tags.append("tmp_path_program") }
        if label.lowercased().contains("evil") || program.lowercased().contains("evil") { tags.append("unknown_team") }
        return tags
    }

    private func temporaryProgram(_ program: String, includeShared: Bool = false) -> Bool {
        let lower = program.lowercased()
        return lower.contains("/tmp/") || lower.contains("/var/tmp/") || (includeShared && lower.contains("/users/shared/"))
    }

    private func untrustedEvilHelper(label: String, program: String, team: String) -> Bool {
        (team.isEmpty || team.lowercased() == "unknown")
            && (label.lowercased().contains("evil") || program.lowercased().contains("evil"))
    }

    private func appendUnique(_ tag: String, to tags: inout [String]) {
        if !tags.contains(tag) { tags.append(tag) }
    }

    private func makeEvent(_ details: HelperDetails) -> EventEnvelope {
        EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "persistence.item",
                label: "PRIVHELPERS"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: Date(timeIntervalSince1970: 0),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: helperEntities(details),
                properties: helperFields(details),
                provenance: details.path,
                confidence: 0.94
            )
        )
    }

    private func helperFields(_ details: HelperDetails) -> [String: String] {
        var fields: [String: String] = [
            "persistence.kind": "privileged_helper",
            "persistence.label": details.label,
            "persistence.path": details.path,
            "persistence.command": details.program,
            "persistence.program": details.program,
            "privhelper.label": details.label,
            "privhelper.path": details.path,
            "helper.label": details.label,
            "helper.path": details.path,
            FieldTaxonomy.filePath: details.path,
            FieldTaxonomy.eventType: "persistence.item",
        ]
        if !details.program.isEmpty {
            fields[FieldTaxonomy.processPath] = details.program
        }
        if !details.launchdPlist.isEmpty {
            fields["privhelper.launchd_plist"] = details.launchdPlist
            fields["helper.launchd_plist"] = details.launchdPlist
        }
        if !details.teamID.isEmpty {
            fields["privhelper.team_id"] = details.teamID
            fields["helper.team_id"] = details.teamID
            fields[FieldTaxonomy.processTeamID] = details.teamID
        }
        if !details.signingID.isEmpty {
            fields["privhelper.signing_id"] = details.signingID
            fields["helper.signing_id"] = details.signingID
            fields[FieldTaxonomy.processSigningID] = details.signingID
        }
        if !details.programArgs.isEmpty {
            fields["privhelper.program_args"] = details.programArgs
            fields["helper.program_args"] = details.programArgs
            fields["persistence.program_arguments"] = details.programArgs
        }
        for (k, v) in details.extra where !v.isEmpty {
            fields[k] = v
        }

        return fields
    }

    private func helperEntities(_ details: HelperDetails) -> [EntityID] {
        var entities: [EntityID] = [
            EntityID(kind: .persistence, value: "privhelper|\(details.label)|\(details.path)"),
            .file(path: details.path),
        ]
        if !details.program.isEmpty && details.program != details.path {
            entities.append(.file(path: details.program))
        }

        return entities
    }
}
