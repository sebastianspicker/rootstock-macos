import Foundation

/// Shared TCC service identifier → display name catalog.
///
/// Seeded from the historical collector registry so graph seeds, red heuristics,
/// and blue parsers can share vocabulary without product types.
public enum TCCServiceCatalog: Sendable {
    /// Display names for known `kTCCService*` identifiers.
    public static let displayNames: [String: String] = [
        // macOS 10.14 Mojave+
        "kTCCServiceAccessibility": "Accessibility",
        "kTCCServiceCalendar": "Calendar",
        "kTCCServiceContacts": "Contacts",
        "kTCCServiceAddressBook": "Address Book",
        "kTCCServicePhotos": "Photos",
        "kTCCServiceReminders": "Reminders",
        "kTCCServiceMicrophone": "Microphone",
        "kTCCServiceCamera": "Camera",
        "kTCCServiceAppleEvents": "Automation",
        "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
        "kTCCServiceScreenCapture": "Screen Recording",
        "kTCCServicePostEvent": "Keyboard Event Injection",
        "kTCCServiceListenEvent": "Input Monitoring",
        "kTCCServiceSystemPolicyDesktopFolder": "Desktop Folder",
        "kTCCServiceSystemPolicyDocumentsFolder": "Documents Folder",
        "kTCCServiceSystemPolicyDownloadsFolder": "Downloads Folder",
        "kTCCServiceSystemPolicyRemovableVolumes": "Removable Volumes",
        "kTCCServiceSystemPolicyNetworkVolumes": "Network Volumes",
        "kTCCServiceEndpointSecurityClient": "Endpoint Security",
        // 10.15 Catalina
        "kTCCServiceSpeechRecognition": "Speech Recognition",
        "kTCCServiceMediaLibrary": "Media Library",
        // 11 Big Sur
        "kTCCServiceBluetoothAlways": "Bluetooth",
        "kTCCServiceUserTracking": "Tracking",
        "kTCCServiceFocusStatus": "Focus Status",
        // 12 Monterey
        "kTCCServiceLocation": "Location Services",
        // 14 Sonoma
        "kTCCServiceSystemPolicySysAdminFiles": "System Admin Files",
        // 15 Sequoia
        "kTCCServiceGameCenterFriends": "Game Center Friends",
        "kTCCServiceWebBrowserPublicKeyCredential": "Web Browser Credentials",
    ]

    /// Minimum macOS major version when known; absent entries predate baseline.
    public static let minimumMajorVersions: [String: Int] = [
        "kTCCServiceSpeechRecognition": 10,
        "kTCCServiceMediaLibrary": 10,
        "kTCCServiceBluetoothAlways": 11,
        "kTCCServiceUserTracking": 11,
        "kTCCServiceFocusStatus": 11,
        "kTCCServiceLocation": 12,
        "kTCCServiceSystemPolicySysAdminFiles": 14,
        "kTCCServiceGameCenterFriends": 15,
        "kTCCServiceWebBrowserPublicKeyCredential": 15,
    ]

    public static let fullDiskAccessService = "kTCCServiceSystemPolicyAllFiles"

    public static func displayName(for service: String) -> String {
        displayNames[service] ?? service
    }

    public static func minimumMajorVersion(for service: String) -> Int? {
        minimumMajorVersions[service]
    }

    public static func isKnown(_ service: String) -> Bool {
        displayNames[service] != nil
    }
}
