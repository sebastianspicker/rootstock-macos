import Foundation
import RootstockCore

#if canImport(Darwin)
import Darwin
#endif

/// Host identity via Foundation / ProcessInfo (no shell).
public struct HostCollector: Collector {
    public static let id = "collect.host"
    public static let cost: CollectorCost = .low

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let info = ProcessInfo.processInfo
        let os = info.operatingSystemVersion
        let osVersion = "\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)"
        let username = NSUserName()
        let hostname = Host.current().localizedName ?? ProcessInfo.processInfo.hostName

        let arch: String
        #if arch(arm64)
        arch = "arm64"
        #elseif arch(x86_64)
        arch = "x86_64"
        #else
        arch = "unknown"
        #endif

        var state = CollectedState()
        state.host = HostState(
            hostname: hostname,
            username: username,
            osVersion: osVersion,
            osBuild: nil,
            arch: arch,
            processArch: arch,
            uptimeSeconds: info.systemUptime,
            isRoot: geteuid() == 0
        )
        state.collectorNotes[Self.id] = "ProcessInfo host snapshot"
        return state
    }
}
