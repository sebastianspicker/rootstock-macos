import Foundation
import RootstockBlueCore

/// Host inventory from SystemVersion.plist and SystemConfiguration preferences.
/// Emits normalized `host.basic_info` envelopes with host entity refs (not a flat CSV dump).
public struct BasicInfoParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "BASICINFO",
        tier: .tier1,
        description: "Host basic info (SystemVersion, ComputerName, HostName)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []

        if let sysURL = root.firstExisting([
            "System/Library/CoreServices/SystemVersion.plist",
            "System/Library/CoreServices/SystemVersion.plist.bak",
        ]) {
            if let e = parseSystemVersion(at: sysURL, root: root) {
                events.append(e)
            }
        }

        // Prefer SystemConfiguration preferences for hostnames
        if let scURL = root.firstExisting([
            "Library/Preferences/SystemConfiguration/preferences.plist",
            "private/var/db/SystemConfiguration/preferences.plist",
        ]) {
            if let e = parseSystemConfiguration(at: scURL) {
                events.append(e)
            }
        }

        // Fallback: walk for SystemVersion if not at standard path
        if events.isEmpty {
            let found = root.enumerate { $0.lastPathComponent == "SystemVersion.plist" }
            for url in found.prefix(1) {
                if let e = parseSystemVersion(at: url, root: root) {
                    events.append(e)
                }
            }
        }

        return events
    }

    private func parseSystemVersion(at url: URL, root: ArtifactRoot) -> EventEnvelope? {
        guard let dict = ArtifactIO.plistDict(contentsOf: url) else { return nil }
        let product = stringValue(dict["ProductName"]) ?? "macOS"
        let version = stringValue(dict["ProductVersion"])
            ?? stringValue(dict["ProductUserVisibleVersion"])
            ?? ""
        let build = stringValue(dict["ProductBuildVersion"]) ?? ""
        guard !version.isEmpty || !build.isEmpty else { return nil }

        let computer = discoverComputerName(root: root) ?? ""
        let hostKey = computer.isEmpty ? "os=\(product)|\(version)|\(build)" : "name=\(computer)"

        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "host.basic_info",
                label: "BASICINFO"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: Date(timeIntervalSince1970: 0),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: hostKey)],
                properties: [
                "host.product_name": product,
                "host.os_version": version,
                "host.os_build": build,
                "host.computer_name": computer,
                "host.source_path": ArtifactRoot.pathKey(url),
                FieldTaxonomy.eventType: "host.basic_info",
            ],
                provenance: ArtifactRoot.pathKey(url),
                confidence: 0.99
            )
        )
    }

    private func parseSystemConfiguration(at url: URL) -> EventEnvelope? {
        guard let dict = ArtifactIO.plistDict(contentsOf: url) else { return nil }
        let system = dict["System"] as? [String: Any]
        let inner = system?["System"] as? [String: Any] ?? system
        let computer = stringValue(inner?["ComputerName"]) ?? ""
        let hostName = stringValue(inner?["HostName"]) ?? ""
        let localHost = stringValue(inner?["LocalHostName"]) ?? ""
        guard !computer.isEmpty || !hostName.isEmpty || !localHost.isEmpty else { return nil }

        let key = computer.isEmpty ? (hostName.isEmpty ? localHost : hostName) : computer
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "host.identity",
                label: "BASICINFO"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: Date(timeIntervalSince1970: 0),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "name=\(key)")],
                properties: [
                "host.computer_name": computer,
                "host.hostname": hostName,
                "host.local_hostname": localHost,
                "host.source_path": ArtifactRoot.pathKey(url),
                FieldTaxonomy.eventType: "host.identity",
            ],
                provenance: ArtifactRoot.pathKey(url),
                confidence: 0.97
            )
        )
    }

    private func discoverComputerName(root: ArtifactRoot) -> String? {
        if let scURL = root.firstExisting([
            "Library/Preferences/SystemConfiguration/preferences.plist",
        ]), let dict = ArtifactIO.plistDict(contentsOf: scURL) {
            let system = dict["System"] as? [String: Any]
            let inner = system?["System"] as? [String: Any] ?? system
            if let name = stringValue(inner?["ComputerName"]), !name.isEmpty {
                return name
            }
        }
        return nil
    }
}
