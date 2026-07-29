import Foundation
import RootstockBlueCore
import RootstockBlueCase

/// KnockKnock-class unified persistence inventory across autostart, BTM, cron,
/// login items, shell profiles, emond, privileged helpers, folder actions,
/// login hooks, authorization plugins, saved-state surface, and optional SSH keys.
public enum PersistenceInventory {
    /// Inventory surface sources merged into a single event list.
    public enum SourceTag: String, Sendable {
        case autostart
        case btm
        case cron
        case loginItem = "login_item"
        case ssh
        case shellProfile = "shell_profile"
        case emond
        case privilegedHelper = "privileged_helper"
        case folderAction = "folder_action"
        case loginHook = "login_hook"
        case authorizationPlugin = "authorization_plugin"
        case savedState = "saved_state"
    }

    /// Run Autostart + BTM + Cron + LoginItems + ShellProfiles + Emond
    /// + PrivHelpers + FolderActions + LoginHooks + AuthPlugins + SavedState
    /// (+ optional SSH authorized_keys) and tag for unified inventory.
    public static func enumerate(source: ImageSource, includeSSH: Bool = true) throws -> [EventEnvelope] {
        try inventoryParsers(includeSSH: includeSSH).flatMap { parser in
            try parser.parse(source: source).compactMap { event in
                normalizedInventoryEvent(event, parserID: parser.manifest.id)
            }
        }
    }

    private static func inventoryParsers(includeSSH: Bool) -> [any ArtifactParser] {
        var parsers: [any ArtifactParser] = [
            AutostartParser(), BTMParser(), CronParser(), LoginItemsParser(),
            ShellProfilesParser(), EmondParser(), PrivHelpersParser(),
            FolderActionsParser(), LoginHooksParser(), AuthPluginsParser(), SavedStateParser(),
        ]
        if includeSSH { parsers.append(SSHArtifactsParser()) }
        return parsers
    }

    private static func normalizedInventoryEvent(_ event: EventEnvelope, parserID: String) -> EventEnvelope? {
        switch parserID {
        case "SSH": return sshInventoryEvent(event, parserID: parserID)
        case "SAVEDSTATE": return savedStateInventoryEvent(event, parserID: parserID)
        default: return standardInventoryEvent(event, parserID: parserID)
        }
    }

    private static func sshInventoryEvent(_ event: EventEnvelope, parserID: String) -> EventEnvelope? {
        guard event.eventType == "auth.ssh_authorized_key" else { return nil }
        var inventoryEvent = event
        inventoryEvent.fields["inventory.source"] = SourceTag.ssh.rawValue
        inventoryEvent.fields["inventory.unified"] = "true"
        inventoryEvent.fields["inventory.parser"] = parserID
        inventoryEvent.fields["inventory.surface"] = "remote_access"
        inventoryEvent.fields["inventory.event_type"] = "access.persistence"
        inventoryEvent.fields["inventory.kind"] = "ssh_authorized_key"
        if inventoryEvent.fields["auth.event_type"] == nil { inventoryEvent.fields["auth.event_type"] = event.eventType }
        inventoryEvent.eventType = "access.persistence"
        inventoryEvent.fields[FieldTaxonomy.eventType] = "access.persistence"
        return inventoryEvent
    }

    private static func savedStateInventoryEvent(_ event: EventEnvelope, parserID: String) -> EventEnvelope? {
        guard isInterestingSavedState(event) else { return nil }
        var inventoryEvent = event
        inventoryEvent.fields["inventory.source"] = SourceTag.savedState.rawValue
        inventoryEvent.fields["inventory.unified"] = "true"
        inventoryEvent.fields["inventory.parser"] = parserID
        inventoryEvent.fields["inventory.kind"] = "saved_state"
        inventoryEvent.fields["inventory.event_type"] = "inventory.persistence"
        if inventoryEvent.fields["persistence.kind"] == nil { inventoryEvent.fields["persistence.kind"] = "saved_state" }
        return inventoryEvent
    }

    private static func isInterestingSavedState(_ event: EventEnvelope) -> Bool {
        let tags = (event.fields["savedstate.risk_tags"] ?? "").lowercased()
        let bundleID = (event.fields["savedstate.bundle_id"] ?? "").lowercased()
        return !tags.isEmpty || bundleID.contains("evil") || bundleID.contains("implant") || !(bundleID.hasPrefix("com.apple.") || bundleID.isEmpty)
    }

    private static func standardInventoryEvent(_ event: EventEnvelope, parserID: String) -> EventEnvelope {
        var inventoryEvent = event
        let tag = sourceTag(for: parserID, event: event)
        inventoryEvent.fields["inventory.source"] = tag.rawValue
        inventoryEvent.fields["inventory.unified"] = "true"
        inventoryEvent.fields["inventory.parser"] = parserID
        if inventoryEvent.fields["inventory.event_type"] == nil { inventoryEvent.fields["inventory.event_type"] = "inventory.persistence" }
        if inventoryEvent.fields["inventory.kind"] == nil {
            inventoryEvent.fields["inventory.kind"] = event.fields["persistence.kind"] ?? event.fields["btm.type_label"] ?? tag.rawValue
        }
        return inventoryEvent
    }

    /// Summarize inventory events by kind / source tag counts.
    public static func summarize(_ events: [EventEnvelope]) -> [String: Int] {
        var counts: [String: Int] = [:]
        for event in events {
            let kind = event.fields["inventory.kind"]
                ?? event.fields["persistence.kind"]
                ?? event.fields["inventory.source"]
                ?? event.eventType
            counts[kind, default: 0] += 1
            if let src = event.fields["inventory.source"] {
                counts["source:\(src)", default: 0] += 1
            }
        }
        counts["total"] = events.count
        return counts
    }

    /// Write inventory events into a case package.
    @discardableResult
    public static func writeToCase(
        _ events: [EventEnvelope],
        package: CasePackage,
        actor: String = NSUserName()
    ) throws -> Int {
        for event in events {
            try package.appendEventJSONL(event, stream: "es")
            try package.insertTimelineEvent(event)
        }
        try package.appendCustody(
            CustodyEvent(
                actor: actor,
                action: "persistence_inventory",
                detail: "Persistence inventory wrote \(events.count) events sources=autostart,btm,cron,login_item,shell_profile,emond,privileged_helper,folder_action,login_hook,authorization_plugin,saved_state,ssh"
            )
        )
        try package.updateHashes()
        return events.count
    }

    // MARK: - Private

    private static let parserSourceTags: [String: SourceTag] = [
        "AUTOSTART": .autostart,
        "BTM": .btm,
        "CRON": .cron,
        "LOGINITEMS": .loginItem,
        "SSH": .ssh,
        "SHELLPROFILES": .shellProfile,
        "EMOND": .emond,
        "PRIVHELPERS": .privilegedHelper,
        "FOLDERACTIONS": .folderAction,
        "LOGINHOOKS": .loginHook,
        "AUTHPLUGINS": .authorizationPlugin,
        "SAVEDSTATE": .savedState,
    ]

    private static let persistenceKindSourceTags: [String: SourceTag] = [
        "cron": .cron,
        "at": .cron,
        "periodic": .cron,
        "login_item": .loginItem,
        "shell_profile": .shellProfile,
        "emond": .emond,
        "privileged_helper": .privilegedHelper,
        "folder_action": .folderAction,
        "login_hook": .loginHook,
        "logout_hook": .loginHook,
        "authorization_plugin": .authorizationPlugin,
        "auth_plugin": .authorizationPlugin,
    ]

    private static func sourceTag(for parserID: String, event: EventEnvelope) -> SourceTag {
        if let parserTag = parserSourceTags[parserID] {
            return parserTag
        }
        if event.eventType.contains("btm") {
            return .btm
        }
        return persistenceKindSourceTags[event.fields["persistence.kind"] ?? ""] ?? .autostart
    }
}
