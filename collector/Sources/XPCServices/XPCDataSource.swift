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
    private let runCommand: ShellCommand

    private static let directories: [(path: String, type: XPCService.ServiceType)] = [
        ("/System/Library/LaunchDaemons", .daemon),
        ("/Library/LaunchDaemons", .daemon),
        ("/Library/LaunchAgents", .agent),
        (NSHomeDirectory() + "/Library/LaunchAgents", .agent),
    ]

    public init() {
        runCommand = { path, arguments, timeout in
            ShellCommandRunner.run(path, arguments, timeout)
        }
    }

    init(
        runCommand: @escaping ShellCommand
    ) {
        self.runCommand = runCommand
    }

    public func collect() async -> DataSourceResult {
        var services: [XPCService] = []
        var errors: [CollectionError] = []

        for (dirPath, serviceType) in Self.directories {
            let (entries, dirErrors) = parser.parseDirectory(at: dirPath)
            for msg in dirErrors {
                errors.append(CollectionError(source: name, message: msg, recoverable: true))
            }
            for entry in entries {
                let built = buildService(from: entry, type: serviceType)
                services.append(built.service)
                if let error = built.error {
                    errors.append(error)
                }
            }
        }

        return DataSourceResult(nodes: services, errors: errors)
    }

    // MARK: - Private

    private func buildService(
        from entry: LaunchdPlistParser.ParsedEntry,
        type: XPCService.ServiceType
    ) -> (service: XPCService, error: CollectionError?) {
        let entitlementResult = entry.program.map(extractEntitlementKeys)
            ?? (keys: [], error: nil)

        return (XPCService(
            label: entry.label,
            path: entry.plistPath,
            program: entry.program,
            type: type,
            launch: XPCService.LaunchBehavior(
                user: entry.user,
                runAtLoad: entry.runAtLoad,
                keepAlive: entry.keepAlive
            ),
            exposure: XPCService.Exposure(
                machServices: entry.machServices,
                entitlements: entitlementResult.keys,
                hasClientVerification: entry.hasAuthorizedClients
            )
        ), entitlementResult.error)
    }

    /// Extract entitlement keys from a signed binary via `codesign -d --entitlements`.
    /// A nonzero codesign exit means unsigned/no entitlements; infrastructure
    /// failures preserve unknown evidence with a recoverable diagnostic.
    func extractEntitlementKeys(
        from path: String
    ) -> (keys: [String], error: CollectionError?) {
        let outcome = runCommand(
            "/usr/bin/codesign",
            ["-d", "--entitlements", ":-", path],
            10
        )
        let result: ShellResult
        switch outcome {
        case .success(let successfulResult):
            result = successfulResult
        case .nonZeroExit:
            return ([], nil)
        case .admissionTimedOut, .launchFailed, .executionTimedOut:
            return ([], CollectionError(
                source: name,
                message: "Entitlements unknown for \(path): \(outcome.failureDescription ?? "command failure")",
                recoverable: true
            ))
        }

        let data = Data(result.stdout.utf8)
        guard !data.isEmpty else { return ([], nil) }

        var format = PropertyListSerialization.PropertyListFormat.xml
        guard let plist = try? PropertyListSerialization.propertyList(
            from: data, options: [], format: &format
        ) as? [String: Any] else {
            return ([], CollectionError(
                source: name,
                message: "Entitlements unknown for \(path): codesign returned an unreadable plist",
                recoverable: true
            ))
        }

        return (Array(plist.keys).sorted(), nil)
    }
}
