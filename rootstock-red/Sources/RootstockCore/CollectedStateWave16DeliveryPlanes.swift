import Foundation
// MARK: - Wave-16 2026 coverage multi-plane surfaces (25 themes / 50 half-pairs)


/// AirPlay receiver dual-use residual (never enables AirPlay Receiver or spoofs AirPlay targets).
public struct AirplayReceiverSurfaceState: Codable, Sendable, Equatable {
    public var airplayDaemonPaths: [String]
    public var airplayPrefPaths: [String]
    public var airplayHelperPaths: [String]
    public var airplaySurfacePresent: Bool?
    public var notes: [String]
    public init(
        airplayDaemonPaths: [String] = [],
        airplayPrefPaths: [String] = [],
        airplayHelperPaths: [String] = [],
        airplaySurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.airplayDaemonPaths = airplayDaemonPaths
        self.airplayPrefPaths = airplayPrefPaths
        self.airplayHelperPaths = airplayHelperPaths
        self.airplaySurfacePresent = airplaySurfacePresent
        self.notes = notes
    }
}


/// Handoff / Universal Clipboard residual depth (never reads Universal Clipboard contents or forges Handoff activity).
public struct HandoffClipboardDepthState: Codable, Sendable, Equatable {
    public var handoffFrameworkPaths: [String]
    public var clipboardPathHits: [String]
    public var sharingdPaths: [String]
    public var handoffSurfacePresent: Bool?
    public var notes: [String]
    public init(
        handoffFrameworkPaths: [String] = [],
        clipboardPathHits: [String] = [],
        sharingdPaths: [String] = [],
        handoffSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.handoffFrameworkPaths = handoffFrameworkPaths
        self.clipboardPathHits = clipboardPathHits
        self.sharingdPaths = sharingdPaths
        self.handoffSurfacePresent = handoffSurfacePresent
        self.notes = notes
    }
}


/// iMessage / Messages path collection plane (never reads Messages database contents or exports chat transcripts).
public struct ImessagePathPlaneState: Codable, Sendable, Equatable {
    public var messagesAppPaths: [String]
    public var messagesDbPaths: [String]
    public var messagesPrefPaths: [String]
    public var imessageSurfacePresent: Bool?
    public var notes: [String]
    public init(
        messagesAppPaths: [String] = [],
        messagesDbPaths: [String] = [],
        messagesPrefPaths: [String] = [],
        imessageSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.messagesAppPaths = messagesAppPaths
        self.messagesDbPaths = messagesDbPaths
        self.messagesPrefPaths = messagesPrefPaths
        self.imessageSurfacePresent = imessageSurfacePresent
        self.notes = notes
    }
}


/// FaceTime / camera pipeline dual-use surface (never activates camera/mic or dumps FaceTime call history contents).
public struct FacetimeCameraSurfaceState: Codable, Sendable, Equatable {
    public var facetimeAppPaths: [String]
    public var avConferencePaths: [String]
    public var facetimePrefPaths: [String]
    public var facetimeSurfacePresent: Bool?
    public var notes: [String]
    public init(
        facetimeAppPaths: [String] = [],
        avConferencePaths: [String] = [],
        facetimePrefPaths: [String] = [],
        facetimeSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.facetimeAppPaths = facetimeAppPaths
        self.avConferencePaths = avConferencePaths
        self.facetimePrefPaths = facetimePrefPaths
        self.facetimeSurfacePresent = facetimeSurfacePresent
        self.notes = notes
    }
}


/// Finder Sync extension dual-use surface (never installs Finder Sync extensions or rewrites Finder preferences for abuse).
public struct FinderSyncExtensionState: Codable, Sendable, Equatable {
    public var finderSyncFrameworkPaths: [String]
    public var appScriptPaths: [String]
    public var finderPrefPaths: [String]
    public var finderSyncSurfacePresent: Bool?
    public var notes: [String]
    public init(
        finderSyncFrameworkPaths: [String] = [],
        appScriptPaths: [String] = [],
        finderPrefPaths: [String] = [],
        finderSyncSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.finderSyncFrameworkPaths = finderSyncFrameworkPaths
        self.appScriptPaths = appScriptPaths
        self.finderPrefPaths = finderPrefPaths
        self.finderSyncSurfacePresent = finderSyncSurfacePresent
        self.notes = notes
    }
}


/// File Provider domain residual surface (never registers malicious File Provider domains or exfiltrates provider caches).
public struct FileproviderDomainState: Codable, Sendable, Equatable {
    public var fileProviderFrameworkPaths: [String]
    public var cloudStoragePaths: [String]
    public var fileProviderLaunchPaths: [String]
    public var fileProviderSurfacePresent: Bool?
    public var notes: [String]
    public init(
        fileProviderFrameworkPaths: [String] = [],
        cloudStoragePaths: [String] = [],
        fileProviderLaunchPaths: [String] = [],
        fileProviderSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.fileProviderFrameworkPaths = fileProviderFrameworkPaths
        self.cloudStoragePaths = cloudStoragePaths
        self.fileProviderLaunchPaths = fileProviderLaunchPaths
        self.fileProviderSurfacePresent = fileProviderSurfacePresent
        self.notes = notes
    }
}


/// Notification Center residual depth (never dumps notification body contents or forges notification payloads).
public struct NotificationCenterDepthState: Codable, Sendable, Equatable {
    public var notificationFrameworkPaths: [String]
    public var notificationStorePaths: [String]
    public var notificationPrefPaths: [String]
    public var notificationSurfacePresent: Bool?
    public var notes: [String]
    public init(
        notificationFrameworkPaths: [String] = [],
        notificationStorePaths: [String] = [],
        notificationPrefPaths: [String] = [],
        notificationSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.notificationFrameworkPaths = notificationFrameworkPaths
        self.notificationStorePaths = notificationStorePaths
        self.notificationPrefPaths = notificationPrefPaths
        self.notificationSurfacePresent = notificationSurfacePresent
        self.notes = notes
    }
}


/// Siri / Suggestions data-access residual (never dumps Siri transcripts or Suggestions databases contents).
public struct SiriSuggestionsPlaneState: Codable, Sendable, Equatable {
    public var siriFrameworkPaths: [String]
    public var suggestionsStorePaths: [String]
    public var siriPrefPaths: [String]
    public var siriSurfacePresent: Bool?
    public var notes: [String]
    public init(
        siriFrameworkPaths: [String] = [],
        suggestionsStorePaths: [String] = [],
        siriPrefPaths: [String] = [],
        siriSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.siriFrameworkPaths = siriFrameworkPaths
        self.suggestionsStorePaths = suggestionsStorePaths
        self.siriPrefPaths = siriPrefPaths
        self.siriSurfacePresent = siriSurfacePresent
        self.notes = notes
    }
}


/// Spotlight importer residual depth (never installs malicious Spotlight importers or dumps mdworker index contents).
public struct SpotlightImporterDepthState: Codable, Sendable, Equatable {
    public var metadataToolPaths: [String]
    public var spotlightImporterPaths: [String]
    public var mdsLaunchPaths: [String]
    public var spotlightImporterSurfacePresent: Bool?
    public var notes: [String]
    public init(
        metadataToolPaths: [String] = [],
        spotlightImporterPaths: [String] = [],
        mdsLaunchPaths: [String] = [],
        spotlightImporterSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.metadataToolPaths = metadataToolPaths
        self.spotlightImporterPaths = spotlightImporterPaths
        self.mdsLaunchPaths = mdsLaunchPaths
        self.spotlightImporterSurfacePresent = spotlightImporterSurfacePresent
        self.notes = notes
    }
}


/// Contacts database path residual plane (never exports contact cards or dumps AddressBook database contents).
public struct ContactsPathPlaneState: Codable, Sendable, Equatable {
    public var contactsAppPaths: [String]
    public var addressBookPaths: [String]
    public var contactsPrefPaths: [String]
    public var contactsSurfacePresent: Bool?
    public var notes: [String]
    public init(
        contactsAppPaths: [String] = [],
        addressBookPaths: [String] = [],
        contactsPrefPaths: [String] = [],
        contactsSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.contactsAppPaths = contactsAppPaths
        self.addressBookPaths = addressBookPaths
        self.contactsPrefPaths = contactsPrefPaths
        self.contactsSurfacePresent = contactsSurfacePresent
        self.notes = notes
    }
}


/// Calendar server / CalDAV residual surface (never reads calendar event bodies or credentials from CalDAV stores).
public struct CalendarServerPathState: Codable, Sendable, Equatable {
    public var caldavFrameworkPaths: [String]
    public var calendarsStorePaths: [String]
    public var calendarAgentPaths: [String]
    public var caldavSurfacePresent: Bool?
    public var notes: [String]
    public init(
        caldavFrameworkPaths: [String] = [],
        calendarsStorePaths: [String] = [],
        calendarAgentPaths: [String] = [],
        caldavSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.caldavFrameworkPaths = caldavFrameworkPaths
        self.calendarsStorePaths = calendarsStorePaths
        self.calendarAgentPaths = calendarAgentPaths
        self.caldavSurfacePresent = caldavSurfacePresent
        self.notes = notes
    }
}


/// Reminders cloud path residual plane (never reads reminder titles/bodies or exports Reminders databases).
public struct RemindersCloudPathState: Codable, Sendable, Equatable {
    public var remindersAppPaths: [String]
    public var remindersStorePaths: [String]
    public var remindersPrefPaths: [String]
    public var remindersCloudSurfacePresent: Bool?
    public var notes: [String]
    public init(
        remindersAppPaths: [String] = [],
        remindersStorePaths: [String] = [],
        remindersPrefPaths: [String] = [],
        remindersCloudSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.remindersAppPaths = remindersAppPaths
        self.remindersStorePaths = remindersStorePaths
        self.remindersPrefPaths = remindersPrefPaths
        self.remindersCloudSurfacePresent = remindersCloudSurfacePresent
        self.notes = notes
    }
}
