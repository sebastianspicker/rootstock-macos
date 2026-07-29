import Foundation
import RootstockBlueCore

/// Preferred / known Wi-Fi networks from SystemConfiguration and known-networks plists.
public struct WifiParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "WIFI",
        tier: .tier2,
        description: "Preferred Wi-Fi networks (airport.preferences / known-networks)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var urls: [URL] = []

        if let primary = root.firstExisting([
            "Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist",
            "Library/Preferences/com.apple.wifi.known-networks.plist",
            "Library/Preferences/wifi_known_networks.json",
            "private/var/preferences/SystemConfiguration/com.apple.airport.preferences.plist",
        ]) {
            ArtifactRoot.appendUnique(&urls, primary)
        }

        // Pick up additional known-network style artifacts anywhere in the tree.
        for found in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "com.apple.airport.preferences.plist"
                || name == "com.apple.wifi.known-networks.plist"
                || name == "wifi_known_networks.json"
        }) {
            ArtifactRoot.appendUnique(&urls, found)
        }

        var events: [EventEnvelope] = []
        var seen = PathDeduper()
        for url in urls {
            if !seen.insert(url) { continue }
            if url.pathExtension == "json" {
                events.append(contentsOf: parseJSON(at: url))
            } else {
                events.append(contentsOf: parsePlist(at: url))
            }
        }
        return events
    }

    private func parseJSON(at url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }

        let entries: [[String: Any]]
        if let arr = obj as? [[String: Any]] {
            entries = arr
        } else if let dict = obj as? [String: Any],
                  let arr = dict["networks"] as? [[String: Any]] {
            entries = arr
        } else if let arr = obj as? [Any] {
            entries = arr.compactMap { $0 as? [String: Any] }
        } else {
            return []
        }

        return entries.compactMap { entry in
            let ssid = stringValue(entry["ssid"]) ?? stringValue(entry["SSID"]) ?? ""
            guard !ssid.isEmpty else { return nil }
            let security = stringValue(entry["security"])
                ?? stringValue(entry["SecurityType"])
                ?? stringValue(entry["security_type"])
                ?? ""
            let lastConnected = stringValue(entry["last_connected"])
                ?? stringValue(entry["LastConnected"])
                ?? ""
            let hidden = boolString(entry["hidden"] ?? entry["Hidden"])
            return makeEvent(
                ssid: ssid,
                security: security,
                lastConnected: lastConnected,
                hidden: hidden,
                sourceURL: url
            )
        }
    }

    private func parsePlist(at url: URL) -> [EventEnvelope] {
        guard let data = ArtifactIO.data(contentsOf: url) else { return [] }
        if let dictionary = ArtifactIO.plistDict(from: data) {
            let dictionaryEvents = plistDictionaryEvents(dictionary, sourceURL: url)
            if !dictionaryEvents.isEmpty { return dictionaryEvents }
        }
        guard let networks = ArtifactIO.plistArray(from: data) else { return [] }
        return networkArrayEvents(networks, sourceURL: url)
    }

    private func plistDictionaryEvents(_ dictionary: [String: Any], sourceURL: URL) -> [EventEnvelope] {
        let knownNetworkEvents = knownNetworkEvents(dictionary, sourceURL: sourceURL)
        if !knownNetworkEvents.isEmpty { return knownNetworkEvents }

        let simplifiedNetworkEvents = simplifiedNetworkEvents(dictionary, sourceURL: sourceURL)
        if !simplifiedNetworkEvents.isEmpty { return simplifiedNetworkEvents }

        return preferredOrderEvents(dictionary, sourceURL: sourceURL)
    }

    private func knownNetworkEvents(_ dictionary: [String: Any], sourceURL: URL) -> [EventEnvelope] {
        guard let networks = dictionary["KnownNetworks"] as? [String: Any] else { return [] }
        return networks.compactMap { key, value in
            guard let network = value as? [String: Any] else { return nil }
            return networkEvent(network, fallbackSSID: key, sourceURL: sourceURL)
        }
    }

    private func simplifiedNetworkEvents(_ dictionary: [String: Any], sourceURL: URL) -> [EventEnvelope] {
        dictionary.compactMap { key, value in
            guard let network = value as? [String: Any], isSimplifiedNetwork(network) else { return nil }
            return networkEvent(network, fallbackSSID: key, sourceURL: sourceURL)
        }
    }

    private func isSimplifiedNetwork(_ network: [String: Any]) -> Bool {
        ["SecurityType", "LastConnected", "SSIDString", "Hidden", "security"]
            .contains { network[$0] != nil }
    }

    private func preferredOrderEvents(_ dictionary: [String: Any], sourceURL: URL) -> [EventEnvelope] {
        guard let order = dictionary["PreferredOrder"] as? [String] else { return [] }
        return order.compactMap { ssid in
            guard !ssid.isEmpty else { return nil }
            return makeEvent(
                ssid: ssid,
                security: "",
                lastConnected: "",
                hidden: "false",
                sourceURL: sourceURL
            )
        }
    }

    private func networkArrayEvents(_ networks: [[String: Any]], sourceURL: URL) -> [EventEnvelope] {
        networks.compactMap { network in
            networkEvent(network, fallbackSSID: "", sourceURL: sourceURL)
        }
    }

    private func networkEvent(
        _ network: [String: Any],
        fallbackSSID: String,
        sourceURL: URL
    ) -> EventEnvelope? {
        let ssid = stringValue(network["SSIDString"]) ?? stringValue(network["SSID"])
            ?? stringValue(network["ssid"]) ?? fallbackSSID
        guard !ssid.isEmpty else { return nil }
        return makeEvent(
            ssid: ssid,
            security: stringValue(network["SecurityType"]) ?? stringValue(network["security"]) ?? "",
            lastConnected: dateString(network["LastConnected"] ?? network["last_connected"]),
            hidden: boolString(network["Hidden"] ?? network["hidden"]),
            sourceURL: sourceURL
        )
    }

    private func makeEvent(
        ssid: String,
        security: String,
        lastConnected: String,
        hidden: String,
        sourceURL: URL
    ) -> EventEnvelope {
        let attrs = try? FileManager.default.attributesOfItem(atPath: sourceURL.path)
        let mtime = (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)
        let eventTime = ISO8601DateFormatter().date(from: lastConnected) ?? mtime

        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "network.wifi_preferred",
                label: "WIFI"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: eventTime,
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [
                EntityID(kind: .network, value: "ssid=\(ssid)"),
            ],
                properties: [
                "wifi.ssid": ssid,
                "wifi.security": security,
                "wifi.last_connected": lastConnected,
                "wifi.hidden": hidden,
                "network.ssid": ssid,
                "wifi.source_path": ArtifactRoot.pathKey(sourceURL),
                FieldTaxonomy.eventType: "network.wifi_preferred",
            ],
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.93
            )
        )
    }

    /// Wi‑Fi plists often store SSID as `Data` (UTF-8 bytes).
    private func stringValue(_ any: Any?) -> String? {
        if let d = any as? Data, let s = String(data: d, encoding: .utf8) { return s }
        return stringish(any)
    }

    private func dateString(_ any: Any?) -> String {
        if let d = parseDate(any) {
            return ISO8601DateFormatter().string(from: d)
        }
        if let s = any as? String { return s }
        return ""
    }

    private func boolString(_ any: Any?) -> String {
        if let b = boolish(any) { return b ? "true" : "false" }
        return "false"
    }
}
