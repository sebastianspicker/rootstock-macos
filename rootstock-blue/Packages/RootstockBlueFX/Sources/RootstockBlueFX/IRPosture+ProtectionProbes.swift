import Foundation
import RootstockBlueCore
import RootstockBlueCase
import RootstockMacFacts

#if canImport(Darwin)
import Darwin
#endif
extension HostIRPosture {
    static func offlineFileVaultMarkers(root: ArtifactRoot) -> [EventEnvelope] {
        // Skip if posture JSON already emitted FileVault (avoid duplicate noise)
        let markers = [
            "var/db/volinfo.database",
            "Library/Preferences/com.apple.FileVault.plist",
            "var/db/FileVault",
        ]
        guard let hit = root.firstExisting(markers) else { return [] }
        // Only emit path-marker event when security_posture.json did not cover FileVault
        if root.exists("Library/Preferences/security_posture.json") {
            return []
        }
        return [
            protectionEvent(
                name: "FileVault",
                enabled: "unknown",
                mode: "offline",
                extra: [
                    "protection.marker_path": ArtifactRoot.pathKey(hit),
                    "protection.note": "FileVault marker present offline; status unknown without fdesetup",
                ],
                rawRef: ArtifactRoot.pathKey(hit),
                confidence: 0.55
            ),
        ]
    }

    static func offlineFirewallALF(root: ArtifactRoot) -> [EventEnvelope] {
        guard let url = root.firstExisting(["Library/Preferences/com.apple.alf.plist"]),
              let dict = ArtifactIO.plistDict(contentsOf: url)
        else { return [] }

        let globalState: Int
        if let i = dict["globalstate"] as? Int {
            globalState = i
        } else if let n = dict["globalstate"] as? NSNumber {
            globalState = n.intValue
        } else {
            globalState = -1
        }
        // ALF: 0 = off, 1 = on for specific, 2 = on for essential
        let enabled: String
        if globalState == 0 { enabled = "false" }
        else if globalState > 0 { enabled = "true" }
        else { enabled = "unknown" }

        return [
            protectionEvent(
                name: "Firewall",
                enabled: enabled,
                mode: "offline",
                extra: [
                    "protection.alf_globalstate": String(globalState),
                    "protection.source": "com.apple.alf.plist",
                    "protection.note": "Application Layer Firewall globalstate from offline plist",
                ],
                rawRef: ArtifactRoot.pathKey(url),
                confidence: enabled == "unknown" ? 0.5 : 0.9
            ),
        ]
    }

    static func offlineXProtectMRT(root: ArtifactRoot) -> [EventEnvelope] {
        guard !root.exists("Library/Preferences/security_posture.json") else { return [] }
        return [
            offlineSecurityToolEvent(root: root, name: "XProtect", entity: "xprotect", paths: ["Library/Apple/System/Library/CoreServices/XProtect.bundle", "System/Library/CoreServices/XProtect.bundle", "Library/Logs/DiagnosticReports"]),
            offlineSecurityToolEvent(root: root, name: "MRT", entity: "mrt", paths: ["Library/Apple/System/Library/CoreServices/MRT.app", "System/Library/CoreServices/MRT.app"]),
        ].compactMap { $0 }
    }

    private static func offlineSecurityToolEvent(root: ArtifactRoot, name: String, entity: String, paths: [String]) -> EventEnvelope? {
        guard let marker = root.firstExisting(paths) else { return nil }
        let path = ArtifactRoot.pathKey(marker)
        return EventEnvelope(
            identity: EventEnvelope.Identity(kind: "ir.posture.protection", label: "IRPOSTURE"),
            capture: EventEnvelope.Capture(source: .collect, eventTime: Date(), collectedAt: Date()),
            payload: EventEnvelope.Payload(entityRefs: [EntityID(kind: .host, value: "protection=\(entity)"), .file(path: path)], properties: ["ir.mode": "offline", "protection.name": name, "protection.enabled": "present", "protection.marker_path": path, FieldTaxonomy.filePath: path, FieldTaxonomy.eventType: "ir.posture.protection"], provenance: path, confidence: 0.7)
        )
    }

    static func offlineFDAHint(root: ArtifactRoot) -> [EventEnvelope] {
        let tccPaths = [
            "Library/Application Support/com.apple.TCC/TCC.db",
            "Users/alice/Library/Application Support/com.apple.TCC/TCC.db",
        ]
        guard let hit = root.firstExisting(tccPaths) else { return [] }
        // If posture JSON already emitted fda_hint, still note TCC.db presence with distinct type detail
        return [
            EventEnvelope(
                identity: EventEnvelope.Identity(
                    kind: "ir.posture.fda_hint",
                    label: "IRPOSTURE"
                ),
                capture: EventEnvelope.Capture(
                    source: .collect,
                    eventTime: Date(),
                    collectedAt: Date()
                ),
                payload: EventEnvelope.Payload(
                    entityRefs: [
                    EntityID(kind: .host, value: "protection=fda"),
                    .file(path: ArtifactRoot.pathKey(hit)),
                ],
                    properties: [
                    "ir.mode": "offline",
                    "protection.name": "FDA",
                    "protection.fda_offline_note":
                        "Offline TCC.db present under artifact tree; FDA grants require live TCC/Full Disk Access check",
                    "protection.tcc_path": ArtifactRoot.pathKey(hit),
                    FieldTaxonomy.filePath: ArtifactRoot.pathKey(hit),
                    FieldTaxonomy.eventType: "ir.posture.fda_hint",
                ],
                    provenance: ArtifactRoot.pathKey(hit),
                    confidence: 0.7
                )
            ),
        ]
    }

    // MARK: - Private

    static func securityProductEvent(name: String, path: String, mode: String) -> EventEnvelope {
        EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "ir.posture.security_product",
                label: "IRPOSTURE"
            ),
            capture: EventEnvelope.Capture(
                source: .collect,
                eventTime: Date(),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [
                EntityID(kind: .host, value: "security=\(name)"),
                .file(path: path),
            ],
                properties: [
                "ir.mode": mode,
                "security.product": name,
                "security.path": path,
                FieldTaxonomy.filePath: path,
                FieldTaxonomy.eventType: "ir.posture.security_product",
            ],
                provenance: path,
                confidence: 0.95
            )
        )
    }

    static func protectionEvent(
        name: String,
        enabled: String,
        mode: String,
        extra: [String: String] = [:],
        rawRef: String? = nil,
        confidence: Double = 0.9
    ) -> EventEnvelope {
        var fields: [String: String] = [
            "ir.mode": mode,
            "protection.name": name,
            "protection.enabled": enabled,
            FieldTaxonomy.eventType: "ir.posture.protection",
        ]
        for (k, v) in extra { fields[k] = v }
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "ir.posture.protection",
                label: "IRPOSTURE"
            ),
            capture: EventEnvelope.Capture(
                source: .collect,
                eventTime: Date(),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "protection=\(name.lowercased())")],
                properties: fields,
                provenance: rawRef,
                confidence: confidence
            )
        )
    }

    static func protectionProbeEvents() -> [EventEnvelope] {
        [
            fileVaultProbeEvent(),
            firewallProbeEvent(),
            sipProbeEvent(),
            gatekeeperProbeEvent(),
        ].compactMap { $0 } + systemExtensionProbeEvents()
    }

    private static func fileVaultProbeEvent() -> EventEnvelope? {
        guard let raw = runProbe(path: HostPostureProbes.fdesetupPath, args: ["status"]) else { return nil }
        let enabled = HostPostureProbes.enabledLabel(HostPostureProbes.parseFileVaultOutput(raw))
        return parsedProbeEvent(name: "FileVault", enabled: enabled, raw: raw)
    }

    private static func sipProbeEvent() -> EventEnvelope? {
        guard let raw = runProbe(path: HostPostureProbes.csrutilPath, args: ["status"]) else { return nil }
        let enabled = HostPostureProbes.enabledLabel(HostPostureProbes.parseSIPOutput(raw))
        return parsedProbeEvent(name: "SIP", enabled: enabled, raw: raw)
    }

    private static func gatekeeperProbeEvent() -> EventEnvelope? {
        guard let raw = runProbe(path: HostPostureProbes.spctlPath, args: ["--status"]) else { return nil }
        let enabled = HostPostureProbes.enabledLabel(HostPostureProbes.parseGatekeeperOutput(raw))
        return parsedProbeEvent(name: "Gatekeeper", enabled: enabled, raw: raw)
    }

    private static func parsedProbeEvent(name: String, enabled: String, raw: String) -> EventEnvelope {
        protectionEvent(name: name, enabled: enabled, mode: "live", extra: ["protection.raw": String(raw.prefix(200)), "protection.parser": "HostPostureProbes"], confidence: enabled == "unknown" ? 0.5 : 0.9)
    }

    private static func firewallProbeEvent() -> EventEnvelope? {
        guard let raw = runProbe(path: "/usr/libexec/ApplicationFirewall/socketfilterfw", args: ["--getglobalstate"]) else { return nil }
        let enabled = firewallProbeState(raw)
        return protectionEvent(name: "Firewall", enabled: enabled, mode: "live", extra: ["protection.raw": String(raw.prefix(200))], confidence: enabled == "unknown" ? 0.5 : 0.9)
    }

    private static func firewallProbeState(_ raw: String) -> String {
        let value = raw.lowercased()
        if value.contains("enabled") && !value.contains("disabled") { return "true" }
        if value.contains("disabled") { return "false" }
        return "unknown"
    }

    private static func systemExtensionProbeEvents() -> [EventEnvelope] {
        guard let raw = runProbe(path: "/usr/bin/systemextensionsctl", args: ["list"]) else { return [] }
        let lines = raw.split(whereSeparator: \.isNewline).map(String.init)
        let extensions = lines.filter(isSystemExtensionDataLine)
        if extensions.isEmpty { return [systemExtensionProbeEvent(name: "none", state: "none", raw: raw, confidence: 0.7)] }
        return extensions.prefix(20).enumerated().map { index, line in
            systemExtensionProbeEvent(name: String(line.trimmingCharacters(in: .whitespaces).prefix(120)), state: "listed", raw: String(line.trimmingCharacters(in: .whitespaces).prefix(200)), confidence: 0.85, index: index)
        }
    }

    private static func isSystemExtensionDataLine(_ line: String) -> Bool {
        let value = line.trimmingCharacters(in: .whitespaces)
        return !value.isEmpty && !value.hasPrefix("---") && !value.lowercased().hasPrefix("extensionname") && !["1 extension", "0 extension"].contains { value.lowercased().contains($0) }
    }

    private static func systemExtensionProbeEvent(name: String, state: String, raw: String, confidence: Double, index: Int? = nil) -> EventEnvelope {
        let entity = index.map { "sysext=\($0)" } ?? "sysext=none"
        return EventEnvelope(
            identity: EventEnvelope.Identity(kind: "ir.posture.system_extension", label: "IRPOSTURE"),
            capture: EventEnvelope.Capture(source: .collect, eventTime: Date(), collectedAt: Date()),
            payload: EventEnvelope.Payload(entityRefs: [EntityID(kind: .host, value: entity)], properties: ["ir.mode": "live", "protection.name": "SystemExtension", "protection.enabled": state == "none" ? "none" : "present", "sysext.name": name, "sysext.state": state, "protection.raw": String(raw.prefix(200)), FieldTaxonomy.eventType: "ir.posture.system_extension"], confidence: confidence)
        )
    }

    static func runProbe(path: String, args: [String]) -> String? {
        guard FileManager.default.isExecutableFile(atPath: path) else { return nil }
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: path)
        proc.arguments = args
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = pipe
        do {
            try proc.run()
        } catch {
            return nil
        }
        // Bound wait - do not hang IR path
        let deadline = Date().addingTimeInterval(3)
        while proc.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }
        if proc.isRunning {
            proc.terminate()
            return nil
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8)
    }

}
