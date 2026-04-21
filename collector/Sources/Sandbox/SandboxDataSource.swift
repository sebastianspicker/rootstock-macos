import Foundation
import Models

/// Extracts sandbox profile data for applications.
///
/// Uses a pragmatic approach for the collector PoC:
/// 1. Reads sandbox-related entitlements (already collected) as rule proxies
/// 2. Checks for system sandbox profiles at known paths
/// 3. Parses any SBPL text found in system profiles
///
/// The real compiled sandbox profiles are binary (Apple's proprietary format).
/// This data source provides a best-effort extraction that covers the most
/// security-relevant information without requiring reverse-engineering the
/// binary format.
public struct SandboxDataSource {
    public let name = "Sandbox"

    /// Known system sandbox profile directory.
    private let systemProfilesPath: String

    /// The SBPL parser for text-based sandbox profiles.
    private let parser = SandboxProfileParser()

    public init(systemProfilesPath: String = "/System/Library/Sandbox/Profiles") {
        self.systemProfilesPath = systemProfilesPath
    }

    // MARK: - Sandbox-related entitlement keys

    /// Entitlement keys that grant file read access.
    static let fileReadEntitlements: Set<String> = [
        "com.apple.security.files.user-selected.read-only",
        "com.apple.security.files.user-selected.read-write",
        "com.apple.security.files.downloads.read-only",
        "com.apple.security.files.downloads.read-write",
        "com.apple.security.files.all",
        "com.apple.security.temporary-exception.files.absolute-path.read-only",
        "com.apple.security.temporary-exception.files.home-relative-path.read-only",
    ]

    /// Entitlement keys that grant file write access.
    static let fileWriteEntitlements: Set<String> = [
        "com.apple.security.files.user-selected.read-write",
        "com.apple.security.files.downloads.read-write",
        "com.apple.security.files.all",
        "com.apple.security.temporary-exception.files.absolute-path.read-write",
        "com.apple.security.temporary-exception.files.home-relative-path.read-write",
    ]

    /// Entitlement keys that grant network access.
    static let networkEntitlements: Set<String> = [
        "com.apple.security.network.client",
        "com.apple.security.network.server",
        "com.apple.security.temporary-exception.mach-lookup.global-name",
    ]

    /// Entitlement keys that represent mach service lookups.
    static let machLookupEntitlements: Set<String> = [
        "com.apple.security.temporary-exception.mach-lookup.global-name",
        "com.apple.security.temporary-exception.mach-lookup.local-name",
        "com.apple.security.temporary-exception.mach-register.global-name",
        "com.apple.security.temporary-exception.mach-register.local-name",
    ]

    /// Entitlement keys that grant IOKit access.
    static let iokitEntitlements: Set<String> = [
        "com.apple.security.temporary-exception.iokit-user-client-class",
    ]

    /// Entitlement keys that indicate unconstrained file access within sandbox.
    static let unconstrainedFileReadEntitlements: Set<String> = [
        "com.apple.security.files.all",
    ]

    /// Entitlement keys that indicate unconstrained network access within sandbox.
    static let unconstrainedNetworkEntitlements: Set<String> = [
        "com.apple.security.network.client",
        "com.apple.security.network.server",
    ]

    // MARK: - Public API

    /// Build a SandboxProfile for a given application using its entitlements
    /// and any matching system sandbox profile.
    public func buildProfile(for app: Application) -> SandboxProfile? {
        guard app.isSandboxed else { return nil }

        let entitlementNames = Set(app.entitlements.map(\.name))

        // Extract rules from entitlements
        let fileReadRules = entitlementNames.intersection(Self.fileReadEntitlements).sorted()
        let fileWriteRules = entitlementNames.intersection(Self.fileWriteEntitlements).sorted()
        let networkRules = entitlementNames.intersection(Self.networkEntitlements).sorted()
        let machLookupRules = entitlementNames.intersection(Self.machLookupEntitlements).sorted()
        let iokitRules = entitlementNames.intersection(Self.iokitEntitlements).sorted()

        // Check for system sandbox profile
        var profileSource = "entitlements"
        var systemRules: SandboxProfileParser.CategorizedRules?

        if let systemProfile = loadSystemProfile(for: app.bundleId) {
            profileSource = "system"
            systemRules = parser.parse(systemProfile)
        }

        // Merge entitlement-derived rules with system profile rules
        var allFileRead = fileReadRules
        var allFileWrite = fileWriteRules
        var allNetwork = networkRules
        var allMachLookup = machLookupRules
        var allIokit = iokitRules

        if let sys = systemRules {
            allFileRead.append(contentsOf: sys.fileReadRules)
            allFileWrite.append(contentsOf: sys.fileWriteRules)
            allNetwork.append(contentsOf: sys.networkRules)
            allMachLookup.append(contentsOf: sys.machLookupRules)
            allIokit.append(contentsOf: sys.iokitRules)
        }

        let exceptionCount = app.sandboxExceptions.count
        let hasUnconstrainedNetwork = !entitlementNames.intersection(Self.unconstrainedNetworkEntitlements).isEmpty
        let hasUnconstrainedFileRead = !entitlementNames.intersection(Self.unconstrainedFileReadEntitlements).isEmpty

        return SandboxProfile(
            bundleId: app.bundleId,
            profileSource: profileSource,
            fileReadRules: allFileRead,
            fileWriteRules: allFileWrite,
            machLookupRules: allMachLookup,
            networkRules: allNetwork,
            iokitRules: allIokit,
            exceptionCount: exceptionCount,
            hasUnconstrainedNetwork: hasUnconstrainedNetwork,
            hasUnconstrainedFileRead: hasUnconstrainedFileRead
        )
    }

    /// Enrich an array of applications with sandbox profile data in place.
    /// Returns the count of profiles added.
    public func enrich(applications: inout [Application]) -> Int {
        let (enriched, count) = enriched(applications: applications)
        applications = enriched
        return count
    }

    /// Return a new array of applications enriched with sandbox profile data.
    /// Uses copy-on-return pattern for safe use with structured concurrency.
    /// Returns the enriched array and the count of profiles added.
    public func enriched(applications: [Application]) -> ([Application], Int) {
        var result = applications
        var count = 0
        for i in result.indices {
            if let profile = buildProfile(for: result[i]) {
                result[i] = result[i].with(sandboxProfile: profile)
                count += 1
            }
        }
        return (result, count)
    }

    // MARK: - System profile loading

    /// Attempt to load a system sandbox profile matching the given bundle ID.
    /// Looks for `<bundleId>.sb` in the system profiles directory.
    func loadSystemProfile(for bundleId: String) -> String? {
        let profilePath = "\(systemProfilesPath)/\(bundleId).sb"
        guard FileManager.default.isReadableFile(atPath: profilePath),
              let data = FileManager.default.contents(atPath: profilePath),
              let text = String(data: data, encoding: .utf8) else {
            return nil
        }
        return text
    }
}
