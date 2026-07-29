import Foundation
import RootstockBlueCore

/// PackageKit installer **design surface** markers (Wave-8 residual red↔blue pair).
///
/// Inventories installer services, receipts, and plugin paths from offline markers.
/// Honesty: path/presence posture only - never builds pkgs or invokes installd.
public struct PackageKitDesignParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "PACKAGEKITDESIGN",
        tier: .tier2,
        description: "PackageKit installer design surface (services/receipts/plugins)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/packagekit_design.json",
            "Library/Logs/packagekit_design.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "packagekit_design.json" || name == "packagekit_design.jsonl"
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
            nestedKeys: ["items", "surfaces", "entries"],
            identityKeys: ["service_present", "receipt_paths", "plugin_paths", "design_surface"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        guard let details = packageKitDetails(from: item, sourceURL: sourceURL) else { return nil }
        let fields = packageKitFields(details: details)
        return packageKitEnvelope(item: item, sourceURL: sourceURL, details: details, fields: fields)
    }

    private struct PackageKitDetails {
        let servicePresent: Bool
        let receiptPaths: [String]
        let pluginPaths: [String]
        let receiptField: String
        let notes: String
        let user: String
        let risk: [String]
    }

    private func packageKitDetails(from item: [String: Any], sourceURL: URL) -> PackageKitDetails? {
        let servicePresent = boolish(item["service_present"]) ?? boolish(item["services_present"]) ?? !stringArray(item["service_paths"]).isEmpty
        let receiptPaths = stringArray(item["receipt_paths"])
        let pluginPaths = stringArray(item["plugin_paths"])
        let designSurface = boolish(item["design_surface"]) ?? (servicePresent || !receiptPaths.isEmpty)
        guard servicePresent || !receiptPaths.isEmpty || !pluginPaths.isEmpty || designSurface else { return nil }
        let receiptField = packageKitReceiptField(item: item, receiptPaths: receiptPaths)
        let risk = packageKitRisk(item: item, servicePresent: servicePresent, receiptPaths: receiptPaths, designSurface: designSurface)
        return PackageKitDetails(servicePresent: servicePresent, receiptPaths: receiptPaths, pluginPaths: pluginPaths, receiptField: receiptField, notes: stringish(item["notes"]) ?? "PackageKit design surface: path presence only - never builds pkgs", user: stringish(item["user"]) ?? inferUser(from: sourceURL.path) ?? "", risk: risk)
    }

    private func packageKitRisk(item: [String: Any], servicePresent: Bool, receiptPaths: [String], designSurface: Bool) -> [String] {
        var risk = (stringish(item["risk_tags"]) ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        if designSurface { appendRisk("design_surface", to: &risk) }
        if servicePresent { appendRisk("installer_service", to: &risk) }
        if !receiptPaths.isEmpty { appendRisk("receipt_inventory", to: &risk) }
        return risk
    }

    private func packageKitReceiptField(item: [String: Any], receiptPaths: [String]) -> String {
        if !receiptPaths.isEmpty { return receiptPaths.joined(separator: ",") }
        return stringish(item["receipt_count"]).flatMap { $0.isEmpty ? nil : $0 } ?? "0"
    }

    private func appendRisk(_ tag: String, to risk: inout [String]) {
        if !risk.contains(tag) { risk.append(tag) }
    }

    private func packageKitFields(details: PackageKitDetails) -> [String: String] {
        var fields = ["packagekit.service_present": details.servicePresent ? "true" : "false", "packagekit.receipt_paths": details.receiptField, "packagekit.plugin_paths": details.pluginPaths.joined(separator: ","), "packagekit.notes": details.notes, FieldTaxonomy.eventType: "packagekit.design", FieldTaxonomy.userName: details.user]
        if !details.risk.isEmpty { fields["packagekit.risk_tags"] = details.risk.joined(separator: ",") }
        return fields
    }

    private func packageKitEnvelope(item: [String: Any], sourceURL: URL, details: PackageKitDetails, fields: [String: String]) -> EventEnvelope {
        EventEnvelope(identity: EventEnvelope.Identity(kind: "packagekit.design", label: "PACKAGEKITDESIGN"), capture: EventEnvelope.Capture(source: .parser, eventTime: parseDate(item["timestamp"] ?? item["collected_at"]) ?? Date(), collectedAt: Date()), payload: EventEnvelope.Payload(entityRefs: [EntityID(kind: .host, value: "packagekit|design|\(details.servicePresent)")], properties: fields, provenance: ArtifactRoot.pathKey(sourceURL), confidence: 0.9))
    }
}
