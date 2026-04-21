import Foundation
import Models

/// Discovers XPC services by parsing launchd plist files from all standard directories.
///
/// Scans:
///   /System/Library/LaunchDaemons  (system daemons)
///   /Library/LaunchDaemons         (third-party daemons)
///   /Library/LaunchAgents          (third-party agents)
///   ~/Library/LaunchAgents         (per-user agents)
///
/// For each service binary, entitlements are extracted via `codesign -d --entitlements`.
/// Unreadable directories produce CollectionErrors rather than crashes.
public struct XPCDataSource: DataSource {
    public let name = "XPC Services"
    public let requiresElevation = false

    private let parser = LaunchdPlistParser()

    private static let directories: [(path: String, type: XPCService.ServiceType)] = [
        ("/System/Library/LaunchDaemons", .daemon),
        ("/Library/LaunchDaemons", .daemon),
        ("/Library/LaunchAgents", .agent),
        (NSHomeDirectory() + "/Library/LaunchAgents", .agent),
    ]

    public init() { }

    public func collect() async -> DataSourceResult {
        var services: [XPCService] = []
        var errors: [CollectionError] = []

        for (dirPath, serviceType) in Self.directories {
            let (entries, dirErrors) = parser.parseDirectory(at: dirPath)
            for msg in dirErrors {
                errors.append(CollectionError(source: name, message: msg, recoverable: true))
            }
            for entry in entries {
                services.append(buildService(from: entry, type: serviceType))
            }
        }

        return DataSourceResult(nodes: services, errors: errors)
    }

    // MARK: - Private

    private func buildService(
        from entry: LaunchdPlistParser.ParsedEntry,
        type: XPCService.ServiceType
    ) -> XPCService {
        let entitlementKeys = entry.program.map(extractEntitlementKeys) ?? []

        return XPCService(
            label: entry.label,
            path: entry.plistPath,
            program: entry.program,
            type: type,
            user: entry.user,
            runAtLoad: entry.runAtLoad,
            keepAlive: entry.keepAlive,
            machServices: entry.machServices,
            entitlements: entitlementKeys,
            hasClientVerification: entry.hasAuthorizedClients
        )
    }

    /// Extract entitlement keys from a signed binary via `codesign -d --entitlements`.
    /// Returns an empty array if the binary is unsigned, inaccessible, or has no entitlements.
    private func extractEntitlementKeys(from path: String) -> [String] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        // `:- ` directs plist output to stdout
        process.arguments = ["-d", "--entitlements", ":-", path]

        let outPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = Pipe()  // discard stderr

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return []
        }

        let data = outPipe.fileHandleForReading.readDataToEndOfFile()
        guard !data.isEmpty else { return [] }

        var format = PropertyListSerialization.PropertyListFormat.xml
        guard let plist = try? PropertyListSerialization.propertyList(
            from: data, options: [], format: &format
        ) as? [String: Any] else { return [] }

        return Array(plist.keys).sorted()
    }
}
