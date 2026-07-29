import Foundation
import RootstockBlueCore
import RootstockBlueCase
import RootstockMacFacts

#if canImport(Darwin)
import Darwin
#endif
extension HostIRPosture {
    static func offlineSecurityPostureJSON(root: ArtifactRoot) -> [EventEnvelope] {
        guard let url = root.firstExisting(["Library/Preferences/security_posture.json"]),
              let json = ArtifactIO.jsonDict(contentsOf: url)
        else { return [] }

        let rawRef = ArtifactRoot.pathKey(url)
        return offlineBasicProtectionEvents(json: json, rawRef: rawRef)
            + offlineVersionProtectionEvents(json: json, rawRef: rawRef)
            + offlineFDAEvents(json: json, rawRef: rawRef)
            + offlineSystemExtensionEvents(json: json, rawRef: rawRef)
            + offlineRemoteAccessEvents(json: json, rawRef: rawRef)
            + offlineGatekeeperAssessmentEvents(json: json, rawRef: rawRef)
            + offlineAccountEvents(json: json, rawRef: rawRef)
            + offlineLockdownEvents(json: json, rawRef: rawRef)
            + offlineSoftwareUpdateEvents(json: json, rawRef: rawRef)
    }

    static func offlineBasicProtectionEvents(json: [String: Any], rawRef: String) -> [EventEnvelope] {
        let booleanProtections = [("filevault_enabled", "FileVault"), ("firewall_enabled", "Firewall")]
        let booleanEvents = booleanProtections.compactMap { key, name -> EventEnvelope? in
            guard let enabled = boolish(json[key]) else { return nil }
            return protectionEvent(
                name: name,
                enabled: enabled ? "true" : "false",
                mode: "offline",
                extra: [
                    "protection.source": "security_posture.json",
                    "protection.note": "Offline synthetic posture JSON (fixture-friendly)",
                ],
                rawRef: rawRef,
                confidence: 0.85
            )
        }
        let statusProtections = [
            ("sip_status", "SIP", "Offline SIP status from posture JSON; live csrutil not run"),
            ("gatekeeper_status", "Gatekeeper", "Offline Gatekeeper status from posture JSON; live spctl not run"),
        ]
        return booleanEvents + statusProtections.compactMap { key, name, note in
            guard let status = json[key] as? String else { return nil }
            return statusProtectionEvent(name: name, status: status, note: note, rawRef: rawRef)
        }
    }

    static func statusProtectionEvent(
        name: String,
        status: String,
        note: String,
        rawRef: String
    ) -> EventEnvelope {
        let lowerStatus = status.lowercased()
        let enabled = lowerStatus.contains("enabled") && !lowerStatus.contains("disabled")
            ? "true"
            : (lowerStatus.contains("disabled") ? "false" : "unknown")
        return protectionEvent(
            name: name,
            enabled: enabled,
            mode: "offline",
            extra: [
                "protection.raw": status,
                "protection.source": "security_posture.json",
                "protection.note": note,
            ],
            rawRef: rawRef,
            confidence: enabled == "unknown" ? 0.5 : 0.8
        )
    }

    static func offlineVersionProtectionEvents(json: [String: Any], rawRef: String) -> [EventEnvelope] {
        [("xprotect_version", "XProtect"), ("mrt_version", "MRT")].compactMap { key, name in
            guard let version = stringish(json[key]), !version.isEmpty else { return nil }
            return protectionEvent(
                name: name,
                enabled: "present",
                mode: "offline",
                extra: [
                    "protection.\(name.lowercased())_version": version,
                    "protection.source": "security_posture.json",
                ],
                rawRef: rawRef,
                confidence: 0.85
            )
        }
    }

    static func offlineFDAEvents(json: [String: Any], rawRef: String) -> [EventEnvelope] {
        guard let apps = json["fda_apps"] as? [Any] else { return [] }
        let names = apps.compactMap { stringish($0) }.joined(separator: ",")
        guard !names.isEmpty else { return [] }
        return [EventEnvelope(
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
                entityRefs: [EntityID(kind: .host, value: "protection=fda")],
                properties: [
                "ir.mode": "offline",
                "protection.name": "FDA",
                "protection.fda_apps": names,
                "protection.fda_offline_note": "Offline FDA app list from posture JSON; live TCC/FDA grants need live check",
                "protection.source": "security_posture.json",
                FieldTaxonomy.eventType: "ir.posture.fda_hint",
            ],
                provenance: rawRef,
                confidence: 0.75
            )
        )]
    }

    static func offlineSystemExtensionEvents(json: [String: Any], rawRef: String) -> [EventEnvelope] {
        guard let extensions = json["system_extensions"] as? [Any] else { return [] }
        return extensions.enumerated().compactMap { index, item in
            systemExtensionEvent(item: item, index: index, rawRef: rawRef)
        }
    }

    static func systemExtensionEvent(item: Any, index: Int, rawRef: String) -> EventEnvelope? {
        let values = item as? [String: Any]
        let name = stringish(item) ?? stringish(values?["name"]) ?? stringish(values?["identifier"]) ?? "sysext_\(index)"
        guard !name.isEmpty else { return nil }
        let team = stringish(values?["team_id"]) ?? stringish(values?["teamID"]) ?? ""
        let state = stringish(values?["state"]) ?? "present"
        var fields: [String: String] = [
            "ir.mode": "offline",
            "protection.name": "SystemExtension",
            "protection.enabled": "present",
            "sysext.name": name,
            "sysext.state": state,
            "protection.source": "security_posture.json",
            "protection.note": "Offline system extension from posture JSON; live systemextensionsctl not run",
            FieldTaxonomy.eventType: "ir.posture.system_extension",
        ]
        if !team.isEmpty { fields["sysext.team_id"] = team }
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "ir.posture.system_extension",
                label: "IRPOSTURE"
            ),
            capture: EventEnvelope.Capture(
                source: .collect,
                eventTime: Date(),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [
                EntityID(kind: .host, value: "sysext=\(name)"),
                EntityID(kind: .persistence, value: "sysext|\(name)"),
            ],
                properties: fields,
                provenance: rawRef,
                confidence: 0.8
            )
        )
    }

    static func offlineRemoteAccessEvents(json: [String: Any], rawRef: String) -> [EventEnvelope] {
        let remoteServices = [
            ("screen_sharing_enabled", "ScreenSharing", "Offline Screen Sharing flag from posture JSON"),
            ("remote_management_enabled", "RemoteManagement", "Offline Remote Management (ARD) flag from posture JSON"),
            ("file_sharing_enabled", "FileSharing", "Offline File Sharing (SMB/AFP) flag from posture JSON"),
        ]
        var events = remoteServices.compactMap { key, name, note -> EventEnvelope? in
            guard let enabled = boolish(json[key]) else { return nil }
            var extra = ["protection.source": "security_posture.json", "protection.note": note]
            if name == "FileSharing" { extra["remote.service"] = "file_sharing" }
            return remoteAccessEvent(name: name, enabled: enabled ? "true" : "false", mode: "offline", extra: extra, rawRef: rawRef, confidence: 0.85)
        }
        if let enabled = boolish(json["remote_login_enabled"]) ?? boolish(json["sshd_enabled"]) {
            events.append(remoteAccessEvent(
                name: "RemoteLogin", enabled: enabled ? "true" : "false", mode: "offline",
                extra: ["remote.service": "ssh", "remote.enabled": enabled ? "true" : "false", "protection.source": "security_posture.json", "protection.note": "Offline Remote Login / sshd service flag from posture JSON"],
                rawRef: rawRef, confidence: 0.85
            ))
        }
        return events
    }

    static func offlineGatekeeperAssessmentEvents(json: [String: Any], rawRef: String) -> [EventEnvelope] {
        guard let assessments = json["gatekeeper_assessments"] as? [Any] else { return [] }
        return assessments.enumerated().compactMap { index, item in
            guard let assessment = item as? [String: Any] else { return nil }
            let path = stringish(assessment["path"]) ?? ""
            let result = stringish(assessment["result"]) ?? "unknown"
            let override = boolish(assessment["override"]) ?? false
            return EventEnvelope(
                identity: EventEnvelope.Identity(
                    kind: "ir.posture.gatekeeper_assessment",
                    label: "IRPOSTURE"
                ),
                capture: EventEnvelope.Capture(
                    source: .collect,
                    eventTime: Date(),
                    collectedAt: Date()
                ),
                payload: EventEnvelope.Payload(
                    entityRefs: [EntityID(kind: .host, value: "gatekeeper=assessment"), path.isEmpty ? EntityID(kind: .host, value: "gk=\(index)") : .file(path: path)],
                    properties: ["ir.mode": "offline", "protection.name": "Gatekeeper", "gatekeeper.path": path, "gatekeeper.result": result, "gatekeeper.override": override ? "true" : "false", "protection.source": "security_posture.json", FieldTaxonomy.filePath: path, FieldTaxonomy.eventType: "ir.posture.gatekeeper_assessment"],
                    provenance: rawRef,
                    confidence: 0.8
                )
            )
        }
    }

    static func offlineAccountEvents(json: [String: Any], rawRef: String) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        if let enabled = boolish(json["guest_account_enabled"]) {
            events.append(accountPostureEvent(kind: "guest", enabled: enabled ? "true" : "false", extra: ["account.guest_enabled": enabled ? "true" : "false", "protection.source": "security_posture.json"], rawRef: rawRef))
        }
        if let enabled = boolish(json["auto_login_enabled"]) {
            var extra = ["account.auto_login_enabled": enabled ? "true" : "false", "protection.source": "security_posture.json"]
            if let user = stringish(json["auto_login_user"]), !user.isEmpty { extra["account.auto_login_user"] = user }
            events.append(accountPostureEvent(kind: "auto_login", enabled: enabled ? "true" : "false", extra: extra, rawRef: rawRef))
        }
        return events
    }

    static func offlineLockdownEvents(json: [String: Any], rawRef: String) -> [EventEnvelope] {
        let enabled: String?
        let rawValue: String?
        if let value = boolish(json["lockdown_mode_enabled"]) {
            enabled = value ? "true" : "false"
            rawValue = nil
        } else if let value = stringish(json["lockdown_mode"]) {
            enabled = normalizedLockdownMode(value)
            rawValue = value
        } else {
            enabled = nil
            rawValue = nil
        }
        guard let enabled else { return [] }
        var extra = ["protection.source": "security_posture.json", "lockdown.enabled": enabled]
        if let rawValue { extra["protection.raw"] = rawValue }
        if rawValue == nil { extra["protection.note"] = "Offline Lockdown Mode from posture JSON (LDMGlobalEnabled class)" }
        return [protectionEvent(name: "LockdownMode", enabled: enabled, mode: "offline", extra: extra, rawRef: rawRef, confidence: enabled == "unknown" ? 0.5 : 0.8)]
    }

    static func normalizedLockdownMode(_ value: String) -> String {
        let lowerValue = value.lowercased()
        if lowerValue.contains("enabled") || lowerValue == "on" || lowerValue == "1" { return "true" }
        if lowerValue.contains("disabled") || lowerValue == "off" || lowerValue == "0" { return "false" }
        return "unknown"
    }

    static func offlineSoftwareUpdateEvents(json: [String: Any], rawRef: String) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        if let enabled = boolish(json["software_update_automatic_check"]) {
            events.append(protectionEvent(name: "SoftwareUpdateAuto", enabled: enabled ? "true" : "false", mode: "offline", extra: ["su.automatic_check": enabled ? "true" : "false", "protection.source": "security_posture.json", "protection.note": "Offline software update automatic check flag"], rawRef: rawRef, confidence: 0.85))
        }
        guard let catalog = stringish(json["software_update_catalog_url"]), !catalog.isEmpty else { return events }
        let isApple = catalog.contains("swscan.apple.com") || catalog.contains("swcdn.apple.com")
        events.append(EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "ir.posture.software_update",
                label: "IRPOSTURE"
            ),
            capture: EventEnvelope.Capture(
                source: .collect,
                eventTime: Date(),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "su=catalog")],
                properties: ["ir.mode": "offline", "protection.name": "SoftwareUpdateCatalog", "protection.enabled": isApple ? "apple_default" : "custom", "su.catalog_url": catalog, "su.catalog_non_apple": isApple ? "false" : "true", "protection.source": "security_posture.json", FieldTaxonomy.eventType: "ir.posture.software_update"],
                provenance: rawRef,
                confidence: 0.9
            )
        ))
        return events
    }

}
