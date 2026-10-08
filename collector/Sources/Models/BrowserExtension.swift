import Foundation

/// A browser extension installed in a Chromium-family, Firefox, or Safari profile.
public struct BrowserExtension: GraphNode {
    public var nodeType: String { "BrowserExtension" }

    /// Browser the extension is installed in.
    public let browser: Browser

    /// Bundle ID of the browser application (e.g., "com.google.Chrome").
    public let browserBundleId: String?

    /// Profile directory name (`Default`, `Profile 1`, Firefox profile folder, `""` for Safari).
    public let profile: String

    /// Chromium extension ID, Firefox add-on ID, or Safari extension bundle ID.
    public let extensionId: String

    /// Manifest name with `__MSG_<key>__` placeholders resolved when possible.
    public let name: String

    /// Installed extension version.
    public let version: String

    /// Manifest `manifest_version`.
    public let manifestVersion: Int?

    /// API permissions declared by the manifest.
    public let permissions: [String]

    /// Host permissions and match patterns declared by the manifest.
    public let hostPermissions: [String]

    /// Whether the extension came from the browser's store (nil when unknown).
    public let fromWebstore: Bool?

    /// Whether the extension is enabled (nil when unknown).
    public let enabled: Bool?

    /// ISO 8601 UTC install time.
    public let installTime: String?

    /// How the extension was installed.
    public let installLocation: InstallLocation

    /// Directory of the installed extension version.
    public let path: String

    public enum Browser: String, Codable, Sendable {
        case chrome
        case chromium
        case brave
        case edge
        case vivaldi
        case arc
        case opera
        case firefox
        case safari
    }

    public enum InstallLocation: String, Codable, Sendable {
        case webstore
        case unpacked
        case external
        case policy
        case component
        case unknown
    }

    /// Manifest-declared capabilities.
    public struct Manifest: Codable, Sendable {
        public let manifestVersion: Int?
        public let permissions: [String]
        public let hostPermissions: [String]

        public init(
            manifestVersion: Int? = nil,
            permissions: [String] = [],
            hostPermissions: [String] = []
        ) {
            self.manifestVersion = manifestVersion
            self.permissions = permissions
            self.hostPermissions = hostPermissions
        }
    }

    /// Install provenance and state from the browser's profile settings.
    public struct Installation: Codable, Sendable {
        public let fromWebstore: Bool?
        public let enabled: Bool?
        public let installTime: String?
        public let installLocation: InstallLocation

        public init(
            fromWebstore: Bool? = nil,
            enabled: Bool? = nil,
            installTime: String? = nil,
            installLocation: InstallLocation = .unknown
        ) {
            self.fromWebstore = fromWebstore
            self.enabled = enabled
            self.installTime = installTime
            self.installLocation = installLocation
        }
    }

    public init(
        browser: Browser,
        browserBundleId: String?,
        profile: String,
        extensionId: String,
        name: String,
        version: String,
        path: String,
        manifest: Manifest = Manifest(),
        installation: Installation = Installation()
    ) {
        self.browser = browser
        self.browserBundleId = browserBundleId
        self.profile = profile
        self.extensionId = extensionId
        self.name = name
        self.version = version
        self.path = path
        self.manifestVersion = manifest.manifestVersion
        self.permissions = manifest.permissions
        self.hostPermissions = manifest.hostPermissions
        self.fromWebstore = installation.fromWebstore
        self.enabled = installation.enabled
        self.installTime = installation.installTime
        self.installLocation = installation.installLocation
    }

    enum CodingKeys: String, CodingKey {
        case browser
        case browserBundleId = "browser_bundle_id"
        case profile
        case extensionId = "extension_id"
        case name
        case version
        case manifestVersion = "manifest_version"
        case permissions
        case hostPermissions = "host_permissions"
        case fromWebstore = "from_webstore"
        case enabled
        case installTime = "install_time"
        case installLocation = "install_location"
        case path
    }
}
