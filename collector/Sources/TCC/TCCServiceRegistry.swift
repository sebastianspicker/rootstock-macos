import Foundation

/// Maps TCC service identifiers to human-readable display names.
///
/// Services are annotated with the minimum macOS major version in which they
/// were introduced. The display-name dictionary always returns a name
/// regardless of version — unknown/future services fall back to the raw
/// identifier string.
enum TCCServiceRegistry {

    // MARK: - Display name table

    private static let names: [String: String] = [

        // ── Available since macOS 10.14 Mojave ────────────────────────────
        "kTCCServiceAccessibility":                 "Accessibility",
        "kTCCServiceCalendar":                      "Calendar",
        "kTCCServiceContacts":                      "Contacts",
        "kTCCServiceAddressBook":                   "Address Book",
        "kTCCServicePhotos":                        "Photos",
        "kTCCServiceReminders":                     "Reminders",
        "kTCCServiceMicrophone":                    "Microphone",
        "kTCCServiceCamera":                        "Camera",
        "kTCCServiceAppleEvents":                   "Automation",
        "kTCCServiceSystemPolicyAllFiles":          "Full Disk Access",
        "kTCCServiceScreenCapture":                 "Screen Recording",
        "kTCCServicePostEvent":                     "Keyboard Event Injection",
        "kTCCServiceListenEvent":                   "Input Monitoring",
        "kTCCServiceSystemPolicyDesktopFolder":     "Desktop Folder",
        "kTCCServiceSystemPolicyDocumentsFolder":   "Documents Folder",
        "kTCCServiceSystemPolicyDownloadsFolder":   "Downloads Folder",
        "kTCCServiceSystemPolicyRemovableVolumes":  "Removable Volumes",
        "kTCCServiceSystemPolicyNetworkVolumes":    "Network Volumes",
        "kTCCServiceEndpointSecurityClient":        "Endpoint Security",

        // ── Added in macOS 10.15 Catalina ─────────────────────────────────
        "kTCCServiceSpeechRecognition":             "Speech Recognition",
        "kTCCServiceMediaLibrary":                  "Media Library",

        // ── Added in macOS 11 Big Sur ─────────────────────────────────────
        "kTCCServiceBluetoothAlways":               "Bluetooth",
        "kTCCServiceUserTracking":                  "Tracking",
        "kTCCServiceFocusStatus":                   "Focus Status",

        // ── Added in macOS 12 Monterey ────────────────────────────────────
        "kTCCServiceLocation":                      "Location Services",

        // ── Added in macOS 14 Sonoma ──────────────────────────────────────
        // Grants access to privileged system administration file paths.
        "kTCCServiceSystemPolicySysAdminFiles":     "System Admin Files",

        // ── Added in macOS 15 Sequoia ─────────────────────────────────────
        // Game Center friends list access.
        "kTCCServiceGameCenterFriends":             "Game Center Friends",
        // In-browser passkey/public-key credential access.
        "kTCCServiceWebBrowserPublicKeyCredential": "Web Browser Credentials",

        // ── macOS 26 Tahoe (year-based versioning, 2025) ──────────────────
        // Core TCC services are inherited from Sequoia.
        // Tahoe-specific additions will be added here as they are documented.
    ]

    // MARK: - Minimum version table

    /// Minimum macOS major version in which a service was introduced.
    /// Services absent from this table predate macOS 14 (our baseline).
    static let minimumMajorVersions: [String: Int] = [
        "kTCCServiceSpeechRecognition":             10,  // Catalina (10.15)
        "kTCCServiceMediaLibrary":                  10,  // Catalina (10.15)
        "kTCCServiceBluetoothAlways":               11,  // Big Sur
        "kTCCServiceUserTracking":                  11,
        "kTCCServiceFocusStatus":                   11,
        "kTCCServiceLocation":                      12,  // Monterey
        "kTCCServiceSystemPolicySysAdminFiles":     14,  // Sonoma
        "kTCCServiceGameCenterFriends":             15,  // Sequoia
        "kTCCServiceWebBrowserPublicKeyCredential": 15,  // Sequoia
    ]

    // MARK: - API

    /// Returns the display name for a TCC service identifier.
    /// Falls back to the raw service identifier for unknown services.
    static func displayName(for service: String) -> String {
        names[service] ?? service
    }

    /// Returns the minimum macOS major version in which `service` was introduced,
    /// or nil if the service predates macOS 11 or is unknown.
    static func minimumMajorVersion(for service: String) -> Int? {
        minimumMajorVersions[service]
    }

    /// Returns true if `service` has a known display name.
    static func isKnown(_ service: String) -> Bool {
        names[service] != nil
    }
}
