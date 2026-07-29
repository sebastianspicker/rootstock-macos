import Foundation
import RootstockBlueCore

/// Code-signing assessment inventory for persistence / helper binaries.
///
/// Offline JSON inventory of `codesign -dv` / notarization collector exports.
/// Links to persistence.kind when the path is a known persistence binary.
/// Does not invoke `codesign` live or unpack Mach-O signatures.
public struct CodesignParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "CODESIGN",
        tier: .tier1,
        description: "Code-sign / notarization assessment inventory for persistence paths"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/codesign_inventory.json",
            "Library/Preferences/persistence_codesign.json",
            "Library/Preferences/com.apple.codesign.inventory.json",
        ] {
            if let url = root.firstExisting([rel]),
               let json = ArtifactIO.jsonObject(contentsOf: url),
               seen.insert(url) {
                events.append(contentsOf: parseJSONInventory(json, rawRef: ArtifactRoot.pathKey(url)))
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "codesign_inventory.json"
                || name == "persistence_codesign.json"
                || name == "com.apple.codesign.inventory.json"
        }) {
            guard seen.insert(url) else { continue }
            if let json = ArtifactIO.jsonObject(contentsOf: url) {
                events.append(contentsOf: parseJSONInventory(json, rawRef: ArtifactRoot.pathKey(url)))
            }
        }

        return events
    }

    private func parseJSONInventory(_ json: Any, rawRef: String) -> [EventEnvelope] {
        var items = ArtifactIO.dictionaryEntries(
            from: json,
            nestedKeys: ["assessments", "items", "binaries", "entries"],
            identityKeys: ["path", "signed"]
        )
        // Preserve prior fallback: bare dict without identity keys still yields one item
        // when nested keys miss (dictionaryEntries with identityKeys already covers path/signed).
        if items.isEmpty, let dict = json as? [String: Any], dict["path"] != nil || dict["signed"] != nil {
            items = [dict]
        }
        return items.compactMap { makeEvent(from: $0, rawRef: rawRef) }
    }

    private struct CodesignFacts {
        let path: String
        let signed: Bool?
        let notarized: Bool?
        let teamID: String
        let signingID: String
        let authority: String
        let persistenceKind: String?
    }

    private func makeEvent(from item: [String: Any], rawRef: String) -> EventEnvelope? {
        guard let facts = codesignFacts(from: item) else { return nil }
        let risk = codesignRiskTags(item: item, facts: facts)
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "codesign.assessment",
                label: "CODESIGN"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: Date(timeIntervalSince1970: 0),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: codesignEntities(for: facts),
                properties: codesignFields(for: facts, risk: risk),
                provenance: rawRef,
                confidence: 0.92
            )
        )
    }

    private func codesignFacts(from item: [String: Any]) -> CodesignFacts? {
        let path = stringish(item["path"]) ?? stringish(item["file"]) ?? stringish(item["file_path"]) ?? stringish(item["binary"]) ?? ""
        guard !path.isEmpty else { return nil }
        let teamID = stringish(item["team_id"]) ?? stringish(item["teamID"]) ?? stringish(item["TeamIdentifier"]) ?? ""
        let signingID = stringish(item["signing_id"]) ?? stringish(item["signingID"]) ?? stringish(item["identifier"]) ?? stringish(item["SigningIdentifier"]) ?? ""
        return CodesignFacts(
            path: path,
            signed: boolish(item["signed"]),
            notarized: boolish(item["notarized"]) ?? boolish(item["notary"]),
            teamID: teamID,
            signingID: signingID,
            authority: stringish(item["authority"]) ?? stringish(item["Authority"]) ?? stringish(item["signer"]) ?? "",
            persistenceKind: stringish(item["persistence_kind"]) ?? stringish(item["persistence.kind"]) ?? inferPersistenceKind(path: path)
        )
    }

    private func codesignRiskTags(item: [String: Any], facts: CodesignFacts) -> [String] {
        var tags = (stringish(item["risk_tags"]) ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        if facts.signed == false { appendRiskTags(["unsigned"], to: &tags) }
        if facts.notarized == false { appendRiskTags(["not_notarized"], to: &tags) }
        if isAdhoc(item: item, facts: facts) { appendRiskTags(["adhoc"], to: &tags) }
        if needsUnknownTeamTag(facts) {
            appendRiskTags(["unknown_team"], to: &tags)
        }
        return tags
    }

    private func isAdhoc(item: [String: Any], facts: CodesignFacts) -> Bool {
        let authority = facts.authority.lowercased()
        return boolish(item["adhoc"]) == true || ["ad-hoc", "adhoc"].contains(where: authority.contains) || facts.teamID == "-"
    }

    private func needsUnknownTeamTag(_ facts: CodesignFacts) -> Bool {
        let unknownTeam = facts.teamID.isEmpty || facts.teamID.uppercased() == "UNKNOWN"
        let suspiciousPath = facts.path.lowercased().contains("evil")
        let suspiciousID = facts.signingID.lowercased().contains("evil")
        return (unknownTeam || suspiciousPath || suspiciousID) && (facts.signed == false || unknownTeam || suspiciousPath)
    }

    private func codesignFields(for facts: CodesignFacts, risk: [String]) -> [String: String] {
        var fields = ["codesign.path": facts.path, FieldTaxonomy.filePath: facts.path, FieldTaxonomy.eventType: "codesign.assessment"]
        addAssessmentFields(for: facts, to: &fields)
        addPersistenceFields(for: facts, risk: risk, to: &fields)
        return fields
    }

    private func addAssessmentFields(for facts: CodesignFacts, to fields: inout [String: String]) {
        addSignatureFields(for: facts, to: &fields)
        addIdentityFields(for: facts, to: &fields)
    }

    private func addSignatureFields(for facts: CodesignFacts, to fields: inout [String: String]) {
        if let signed = facts.signed { fields["codesign.signed"] = signed ? "true" : "false"; fields[FieldTaxonomy.processSigned] = signed ? "true" : "false" }
        if let notarized = facts.notarized { fields["codesign.notarized"] = notarized ? "true" : "false" }
    }

    private func addIdentityFields(for facts: CodesignFacts, to fields: inout [String: String]) {
        if !facts.teamID.isEmpty { fields["codesign.team_id"] = facts.teamID; fields[FieldTaxonomy.processTeamID] = facts.teamID }
        if !facts.signingID.isEmpty { fields["codesign.signing_id"] = facts.signingID; fields[FieldTaxonomy.processSigningID] = facts.signingID }
        if !facts.authority.isEmpty { fields["codesign.authority"] = facts.authority }
    }

    private func addPersistenceFields(for facts: CodesignFacts, risk: [String], to fields: inout [String: String]) {
        if let kind = facts.persistenceKind, !kind.isEmpty { fields["persistence.kind"] = kind; fields["codesign.persistence_kind"] = kind }
        if !risk.isEmpty { fields["codesign.risk_tags"] = risk.joined(separator: ","); fields["persistence.risk_tags"] = risk.joined(separator: ",") }
    }

    private func codesignEntities(for facts: CodesignFacts) -> [EntityID] {
        var entities: [EntityID] = [.file(path: facts.path), EntityID(kind: .host, value: "codesign|\(facts.path)|\(facts.teamID)")]
        if let kind = facts.persistenceKind, !kind.isEmpty { entities.append(EntityID(kind: .persistence, value: "\(kind)|\(facts.path)")) }
        return entities
    }

    private func appendRiskTags(_ additions: [String], to tags: inout [String]) {
        for tag in additions where !tags.contains(tag) { tags.append(tag) }
    }

    private func inferPersistenceKind(path: String) -> String? {
        let lower = path.lowercased()
        for (marker, kind) in Self.persistenceKindMarkers where lower.contains(marker) {
            return kind
        }
        return nil
    }

    private static let persistenceKindMarkers: [(String, String)] = [
        ("privilegedhelpertools", "privileged_helper"), ("launchagents", "launchd"),
        ("launchdaemons", "launchd"), ("securityagentplugins", "authorization_plugin"),
        ("loginhook", "login_hook"), ("login_hook", "login_hook"),
        ("/library/launch", "launchd"), ("privhelper", "privileged_helper"),
        ("persist", "launchd"),
    ]
}
