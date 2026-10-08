import Foundation

/// An installer package receipt from `/var/db/receipts/`.
public struct InstalledPackage: GraphNode {
    public var nodeType: String { "InstalledPackage" }

    /// `PackageIdentifier` (fallback: receipt plist basename).
    public let packageId: String

    /// `PackageVersion`.
    public let version: String?

    /// `InstallDate` as ISO 8601 UTC.
    public let installDate: String?

    /// `InstallPrefixPath`.
    public let installPrefix: String?

    /// `InstallProcessName`.
    public let installProcess: String?

    /// `PackageFileName`.
    public let packageFileName: String?

    /// Whether the package identifier starts with `com.apple.`.
    public let isApple: Bool

    public init(
        packageId: String,
        version: String? = nil,
        installDate: String? = nil,
        installPrefix: String? = nil,
        installProcess: String? = nil,
        packageFileName: String? = nil
    ) {
        self.packageId = packageId
        self.version = version
        self.installDate = installDate
        self.installPrefix = installPrefix
        self.installProcess = installProcess
        self.packageFileName = packageFileName
        self.isApple = packageId.hasPrefix("com.apple.")
    }

    enum CodingKeys: String, CodingKey {
        case packageId = "package_id"
        case version
        case installDate = "install_date"
        case installPrefix = "install_prefix"
        case installProcess = "install_process"
        case packageFileName = "package_file_name"
        case isApple = "is_apple"
    }
}
