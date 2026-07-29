import Foundation
import RootstockBlueCore

/// TCC / ESF **visibility depth** markers (Wave-8 residual red↔blue pair).
///
/// Labels operator visibility as strong / partial / thin from offline markers.
/// Never dumps TCC.db rows or live-subscribes Endpoint Security.
public struct TCCESFVisibilityParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "TCCESFVISIBILITY",
        tier: .tier2,
        description: "TCC/ESF visibility depth (strong|partial|thin)"
    )

    private struct VisibilityReport {
        let tccListable: Bool
        let toolPresent: Bool
        let toolPath: String
        let user: String
    }

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/tcc_esf_visibility.json",
            "Library/Logs/tcc_esf_visibility.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "tcc_esf_visibility.json" || name == "tcc_esf_visibility.jsonl"
        }) where seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
        }

        return events
    }

    private func parseFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" {
            return ArtifactIO.jsonlDictionaries(contentsOf: url)
                .compactMap { makeEvent(from: $0, sourceURL: url) }
        }
        return ArtifactIO.jsonDictionaryEntries(
            contentsOf: url,
            nestedKeys: ["items", "entries", "visibility"],
            identityKeys: ["depth", "visibility_depth", "tcc_path_listable", "tool_present"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let report = VisibilityReport(
            tccListable: boolish(item["tcc_path_listable"]) ?? boolish(item["tcc_listable"])
                ?? boolish(item["tcc_readable"]) ?? false,
            toolPresent: boolish(item["tool_present"])
                ?? stringish(item["tool_path"]).map { !$0.isEmpty } ?? false,
            toolPath: stringish(item["tool_path"]) ?? stringish(item["visibility_tool"]) ?? "",
            user: stringish(item["user"]) ?? inferUser(from: sourceURL.path) ?? ""
        )
        let depth = visibilityDepth(item: item, tccListable: report.tccListable, toolPresent: report.toolPresent)
        let risk = visibilityRiskTags(item: item, depth: depth)

        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "tcc_esf.visibility",
                label: "TCCESFVISIBILITY"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: parseDate(item["timestamp"] ?? item["assessed_at"]) ?? Date(),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "visibility|\(depth)|\(report.toolPresent)")],
                properties: visibilityFields(depth: depth, report: report, risk: risk),
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.9
            )
        )
    }

    private func visibilityDepth(item: [String: Any], tccListable: Bool, toolPresent: Bool) -> String {
        let reported = (stringish(item["depth"]) ?? stringish(item["visibility_depth"]) ?? "").lowercased()
        if ["strong", "partial", "thin"].contains(reported) { return reported }
        if tccListable && toolPresent { return "strong" }
        return tccListable || toolPresent ? "partial" : "thin"
    }

    private func visibilityRiskTags(item: [String: Any], depth: String) -> [String] {
        var risk = visibilityItemRiskTags(item)
        switch depth {
        case "thin":
            appendVisibilityRiskTag("thin_visibility", to: &risk)
            appendVisibilityRiskTag("sensor_gap_adjacent", to: &risk)
        case "partial":
            appendVisibilityRiskTag("partial_visibility", to: &risk)
        default:
            break
        }
        return risk
    }

    private func visibilityItemRiskTags(_ item: [String: Any]) -> [String] {
        guard let tags = stringish(item["risk_tags"]), !tags.isEmpty else { return [] }
        return tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
    }

    private func appendVisibilityRiskTag(_ tag: String, to risk: inout [String]) {
        guard !risk.contains(tag) else { return }
        risk.append(tag)
    }

    private func visibilityFields(
        depth: String,
        report: VisibilityReport,
        risk: [String]
    ) -> [String: String] {
        var fields: [String: String] = [
            "visibility.depth": depth,
            "visibility.tcc_path_listable": report.tccListable ? "true" : "false",
            "visibility.tool_present": report.toolPresent ? "true" : "false",
            "visibility.tool_path": report.toolPath,
            FieldTaxonomy.eventType: "tcc_esf.visibility",
            FieldTaxonomy.userName: report.user,
        ]
        if !risk.isEmpty { fields["visibility.risk_tags"] = risk.joined(separator: ",") }
        return fields
    }
}
