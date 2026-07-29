import Foundation
import RootstockBlueCore
import RootstockBlueCase
import RootstockMacFacts

#if canImport(Darwin)
import Darwin
#endif

/// Defensive host IR posture enumeration - sibling DNA from MacEnumKit
/// protections/host collectors, inverted to **defensive case I/O**: emits
/// normalized `EventEnvelope`s with entity refs into `.rsbcase`.
///
/// Live SIP/Gatekeeper/FileVault parsing uses `HostPostureProbes` (RootstockMacFacts).
/// Offline evidence-tree mode never requires live probes.
public enum HostIRPosture {
    /// Catalog of security products (path presence only - no process storm).
    public static let securityProductCatalog: [(name: String, path: String)] = [
        ("CrowdStrike Falcon", "/Library/CS/falconctl"),
        ("CrowdStrike Falcon", "/Applications/Falcon.app"),
        ("Santa", "/Applications/Santa.app"),
        ("Santa", "/usr/local/bin/santactl"),
        ("osquery", "/usr/local/bin/osqueryd"),
        ("osquery", "/opt/osquery/bin/osqueryd"),
        ("Microsoft Defender", "/Applications/Microsoft Defender.app"),
        ("Jamf Protect", "/Library/Application Support/JamfProtect"),
        ("Jamf", "/usr/local/bin/jamf"),
        ("Elastic Endpoint", "/Library/Elastic/Endpoint"),
        ("LuLu", "/Applications/LuLu.app"),
        ("Little Snitch", "/Applications/Little Snitch.app"),
        ("Carbon Black", "/Applications/VMware Carbon Black Cloud.app"),
        ("SentinelOne", "/Library/Sentinel/sentinel-agent.bundle"),
    ]

    /// Enumerate posture from an offline artifact tree (fixture / image root).
    public static func enumerateOffline(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events = offlineHostIdentityEvents(root: root)
        events.append(contentsOf: offlineSecurityProductEvents(root: root))
        events.append(contentsOf: offlineArtifactPostureEvents(root: root))
        events.append(contentsOf: offlinePreferencePostureEvents(root: root))
        if events.isEmpty {
            events.append(offlineEmptyScanEvent())
        }
        return events
    }

    private static func offlineHostIdentityEvents(root: ArtifactRoot) -> [EventEnvelope] {
        guard let systemVersionURL = root.firstExisting(["System/Library/CoreServices/SystemVersion.plist"]),
              let dictionary = ArtifactIO.plistDict(contentsOf: systemVersionURL) else { return [] }
        let version = (dictionary["ProductVersion"] as? String) ?? ""
        let build = (dictionary["ProductBuildVersion"] as? String) ?? ""
        let product = (dictionary["ProductName"] as? String) ?? "macOS"
        return [EventEnvelope(
            identity: EventEnvelope.Identity(kind: "ir.posture.host", label: "IRPOSTURE"),
            capture: EventEnvelope.Capture(source: .collect, eventTime: Date(), collectedAt: Date()),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "os=\(product)|\(version)|\(build)")],
                properties: [
                    "ir.mode": "offline",
                    "host.product_name": product,
                    "host.os_version": version,
                    "host.os_build": build,
                    FieldTaxonomy.eventType: "ir.posture.host",
                ],
                provenance: ArtifactRoot.pathKey(systemVersionURL),
                confidence: 0.98
            )
        )]
    }

    private static func offlineSecurityProductEvents(root: ArtifactRoot) -> [EventEnvelope] {
        var seenProducts = Set<String>()
        return securityProductCatalog.compactMap { name, absolutePath in
            let relativePath = absolutePath.hasPrefix("/") ? String(absolutePath.dropFirst()) : absolutePath
            let candidate = root.file(relativePath)
            guard FileManager.default.fileExists(atPath: candidate.path), seenProducts.insert(name).inserted else { return nil }
            return securityProductEvent(name: name, path: candidate.path, mode: "offline")
        }
    }

    private static func offlineArtifactPostureEvents(root: ArtifactRoot) -> [EventEnvelope] {
        [
            offlineSecurityPostureJSON(root: root),
            offlineFileVaultMarkers(root: root),
            offlineFirewallALF(root: root),
            offlineXProtectMRT(root: root),
            offlineFDAHint(root: root),
            offlineSystemExtensions(root: root),
            offlineRemoteAccessSignals(root: root),
            offlineGatekeeperAssessments(root: root),
            offlineAccountAndLoginwindow(root: root),
            offlineFileSharingMarkers(root: root),
            offlineSoftwareUpdateMarkers(root: root),
            offlineLockdownModeMarkers(root: root),
            offlineARDMarkers(root: root),
        ].flatMap { $0 }
    }

    private static func offlinePreferencePostureEvents(root: ArtifactRoot) -> [EventEnvelope] {
        guard root.exists("Library/Preferences/com.apple.security.plist") || root.exists("Library/Preferences/com.apple.systempolicy.plist") else { return [] }
        return [EventEnvelope(
            identity: EventEnvelope.Identity(kind: "ir.posture.protection", label: "IRPOSTURE"),
            capture: EventEnvelope.Capture(source: .collect, eventTime: Date(), collectedAt: Date()),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "protections=prefs_present")],
                properties: [
                    "ir.mode": "offline",
                    "protection.name": "Gatekeeper",
                    "protection.enabled": "unknown",
                    "protection.gatekeeper_prefs": "present",
                    "protection.note": "Offline prefs marker only; live csrutil/spctl not run",
                    FieldTaxonomy.eventType: "ir.posture.protection",
                ],
                confidence: 0.6
            )
        )]
    }

    private static func offlineEmptyScanEvent() -> EventEnvelope {
        EventEnvelope(
            identity: EventEnvelope.Identity(kind: "ir.posture.scan", label: "IRPOSTURE"),
            capture: EventEnvelope.Capture(source: .collect, eventTime: Date(), collectedAt: Date()),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "scan=offline")],
                properties: [
                    "ir.mode": "offline",
                    "ir.products_found": "0",
                    "ir.note": "No SystemVersion or known security products under artifact root",
                    FieldTaxonomy.eventType: "ir.posture.scan",
                ],
                confidence: 0.7
            )
        )
    }

    /// Live host posture (ProcessInfo + path catalog). Optional allowlisted status probes.
    /// Does not enable AUTH/block. Honest about probe failures.
    public static func enumerateLive(runStatusProbes: Bool = true) -> [EventEnvelope] {
        var events = [liveHostEvent()]
        events.append(contentsOf: liveSecurityProductEvents())
        if runStatusProbes {
            events.append(contentsOf: protectionProbeEvents())
        }
        return events
    }

    private static func liveHostEvent() -> EventEnvelope {
        let info = ProcessInfo.processInfo
        let os = info.operatingSystemVersion
        let osVersion = "\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)"
        let hostname = info.hostName
        let username = NSUserName()
        let architecture = liveArchitecture()
        return EventEnvelope(
            identity: EventEnvelope.Identity(kind: "ir.posture.host", label: "IRPOSTURE"),
            capture: EventEnvelope.Capture(source: .collect, eventTime: Date(), collectedAt: Date()),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "name=\(hostname)"), .user(name: username)],
                properties: [
                    "ir.mode": "live",
                    "host.hostname": hostname,
                    "host.os_version": osVersion,
                    "host.arch": architecture,
                    "host.username": username,
                    "host.uptime_seconds": String(Int(info.systemUptime)),
                    FieldTaxonomy.userName: username,
                    FieldTaxonomy.eventType: "ir.posture.host",
                ],
                confidence: 0.99
            )
        )
    }

    private static func liveArchitecture() -> String {
        #if arch(arm64)
        return "arm64"
        #elseif arch(x86_64)
        return "x86_64"
        #else
        return "unknown"
        #endif
    }

    private static func liveSecurityProductEvents() -> [EventEnvelope] {
        var seenProducts = Set<String>()
        return securityProductCatalog.compactMap { name, path in
            guard FileManager.default.fileExists(atPath: path), seenProducts.insert(name).inserted else { return nil }
            return securityProductEvent(name: name, path: path, mode: "live")
        }
    }

    /// Write posture events into a case (JSONL + timeline + custody + hashes).
    @discardableResult
    public static func writeToCase(
        _ events: [EventEnvelope],
        package: CasePackage,
        actor: String = NSUserName(),
        mode: String
    ) throws -> Int {
        for event in events {
            try package.appendEventJSONL(event, stream: "es")
            try package.insertTimelineEvent(event)
        }
        try package.appendCustody(
            CustodyEvent(
                actor: actor,
                action: "ir_posture",
                detail: "IR posture (\(mode)) wrote \(events.count) events plugins=IRPOSTURE"
            )
        )
        try package.updateHashes()
        return events.count
    }

    // MARK: - Offline protection helpers

}
