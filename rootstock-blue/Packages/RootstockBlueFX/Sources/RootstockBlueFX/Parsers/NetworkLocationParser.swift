import Foundation
import RootstockBlueCore

/// Network locations / services from SystemConfiguration preferences or
/// fixture `network_locations.json`.
public struct NetworkLocationParser: ArtifactParser {
    private struct LocationDetails {
        let service: String
        let interface: String
        let ipv4: String
        let location: String
        let sourceURL: URL
        let extra: [String: Any]
    }

    public let manifest = PluginManifest(
        id: "NETLOCATION",
        tier: .tier2,
        description: "Network locations and interface/service configuration"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var urls: [URL] = []
        var seen = PathDeduper()

        appendURLs(root.enumerate(matching: { Self.isNetworkLocationFile($0) }), to: &urls, seen: &seen)
        appendURLs(standardURLs(in: root), to: &urls, seen: &seen)
        return urls.flatMap(parseFile)
    }

    private func standardURLs(in root: ArtifactRoot) -> [URL] {
        [
            "Library/Preferences/SystemConfiguration/network_locations.json",
            "Library/Preferences/SystemConfiguration/preferences.plist",
            "Library/Preferences/network_locations.json",
        ].compactMap { root.firstExisting([$0]) }
    }

    private static func isNetworkLocationFile(_ url: URL) -> Bool {
        url.lastPathComponent == "network_locations.json"
            || (url.lastPathComponent == "preferences.plist" && url.path.contains("SystemConfiguration"))
    }

    private func appendURLs(_ candidates: [URL], to urls: inout [URL], seen: inout PathDeduper) {
        for url in candidates where seen.insert(url) {
            ArtifactRoot.appendUnique(&urls, url)
        }
    }

    private func parseFile(_ url: URL) -> [EventEnvelope] {
        url.pathExtension == "json" ? parseJSON(at: url) : parsePreferencesPlist(at: url)
    }

    // MARK: - JSON fixture

    private func parseJSON(at url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }

        let entries: [[String: Any]]
        if let arr = obj as? [[String: Any]] {
            entries = arr
        } else if let dict = obj as? [String: Any] {
            if let arr = dict["locations"] as? [[String: Any]] {
                entries = arr
            } else if let arr = dict["services"] as? [[String: Any]] {
                entries = arr
            } else if let arr = dict["items"] as? [[String: Any]] {
                entries = arr
            } else {
                return []
            }
        } else {
            return []
        }

        return entries.compactMap { item in
            makeEvent(LocationDetails(
                service: stringValue(item["service"])
                    ?? stringValue(item["name"])
                    ?? stringValue(item["UserDefinedName"])
                    ?? "",
                interface: stringValue(item["interface"])
                    ?? interfaceFromNested(item)
                    ?? "",
                ipv4: stringValue(item["ipv4"])
                    ?? stringValue(item["IPv4"])
                    ?? ipv4FromNested(item)
                    ?? "",
                location: stringValue(item["location"]) ?? stringValue(item["Location"]) ?? "",
                sourceURL: url,
                extra: item
            ))
        }
    }

    // MARK: - SystemConfiguration preferences.plist

    private func parsePreferencesPlist(at url: URL) -> [EventEnvelope] {
        guard let rootDict = ArtifactIO.plistDict(contentsOf: url) else { return [] }
        let serviceEvents = eventsFromServices(rootDict["NetworkServices"], sourceURL: url)
        return serviceEvents.isEmpty
            ? eventsFromLocations(rootDict["Sets"], sourceURL: url)
            : serviceEvents
    }

    private func eventsFromServices(_ value: Any?, sourceURL: URL) -> [EventEnvelope] {
        guard let services = value as? [String: Any] else { return [] }
        return services.compactMap { uuid, value in
            guard let service = value as? [String: Any] else { return nil }
            return makeEvent(LocationDetails(
                service: stringValue(service["UserDefinedName"]) ?? uuid,
                interface: interfaceFromNested(service) ?? "",
                ipv4: ipv4FromNested(service) ?? "",
                location: "",
                sourceURL: sourceURL,
                extra: service
            ))
        }
    }

    private func eventsFromLocations(_ value: Any?, sourceURL: URL) -> [EventEnvelope] {
        guard let sets = value as? [String: Any] else { return [] }
        for value in sets.values {
            guard let set = value as? [String: Any],
                  let location = stringValue(set["UserDefinedName"]),
                  !location.isEmpty
            else { continue }
            if let event = makeEvent(LocationDetails(
                service: location,
                interface: "",
                ipv4: "",
                location: location,
                sourceURL: sourceURL,
                extra: set
            )) {
                return [event]
            }
        }
        return []
    }

    // MARK: - event

    private func makeEvent(_ details: LocationDetails) -> EventEnvelope? {
        guard !details.service.isEmpty || !details.interface.isEmpty || !details.ipv4.isEmpty else { return nil }

        var fields: [String: String] = [
            "net.service": details.service,
            "net.interface": details.interface,
            FieldTaxonomy.eventType: "net.location",
            FieldTaxonomy.filePath: ArtifactRoot.pathKey(details.sourceURL),
        ]
        if !details.ipv4.isEmpty {
            fields["net.ipv4"] = details.ipv4
        }
        if !details.location.isEmpty {
            fields["net.location_name"] = details.location
        }
        if let mac = stringValue(details.extra["mac"]) ?? stringValue(details.extra["MAC"]) {
            fields["net.mac"] = mac
        }

        var entities: [EntityID] = [
            EntityID(kind: .network, value: "service=\(details.service.isEmpty ? details.interface : details.service)"),
        ]
        if !details.ipv4.isEmpty {
            entities.append(EntityID(kind: .network, value: "ipv4=\(details.ipv4)"))
        }

        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "net.location",
                label: "NETLOCATION"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: fileMTime(details.sourceURL),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: entities,
                properties: fields,
                provenance: ArtifactRoot.pathKey(details.sourceURL),
                confidence: 0.9
            )
        )
    }

    private func interfaceFromNested(_ item: [String: Any]) -> String? {
        if let iface = item["Interface"] as? [String: Any] {
            return stringValue(iface["DeviceName"])
                ?? stringValue(iface["Hardware"])
                ?? stringValue(iface["Type"])
        }
        if let s = stringValue(item["DeviceName"]) { return s }
        if let s = stringValue(item["BSD Name"]) { return s }
        return nil
    }

    private func ipv4FromNested(_ item: [String: Any]) -> String? {
        if let ip = item["IPv4"] as? [String: Any] {
            if let addrs = ip["Addresses"] as? [String], let first = addrs.first {
                return first
            }
            if let addr = stringValue(ip["Address"]) { return addr }
            if let addr = stringValue(ip["Router"]) { return addr }
        }
        if let s = stringValue(item["Addresses"]) { return s }
        return nil
    }

    private func fileMTime(_ url: URL) -> Date {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)
    }
}
