import Foundation
import HostCommand
import Models

/// Lists listening TCP sockets and bound UDP sockets with their owning process.
///
/// Uses `netstat -anv` (pid column) and one `ps axo pid=,user=,comm=` run to
/// resolve each pid to its user and executable, then maps executables inside a
/// discovered `.app` bundle to that application's bundle ID.
public struct NetworkListenersDataSource: DataSource {
    public let name = "Network Listeners"
    public let requiresElevation = false

    static let netstatPath = "/usr/sbin/netstat"
    static let psPath = "/bin/ps"

    private let knownApps: [Application]
    private let runCommand: ShellCommand

    public init(knownApps: [Application] = []) {
        self.knownApps = knownApps
        self.runCommand = { path, arguments, timeout in
            ShellCommandRunner.run(path, arguments, timeout)
        }
    }

    init(knownApps: [Application] = [], runCommand: @escaping ShellCommand) {
        self.knownApps = knownApps
        self.runCommand = runCommand
    }

    public func collect() async -> DataSourceResult {
        var errors: [CollectionError] = []
        var sockets: [NetstatSocket] = []
        for transport in ["tcp", "udp"] {
            let outcome = runCommand(Self.netstatPath, ["-anv", "-p", transport], Shell.defaultTimeoutSeconds)
            guard case .success(let result) = outcome else {
                errors.append(error("netstat -anv -p \(transport) failed: \(outcome.failureDescription ?? "unknown failure")"))
                continue
            }
            // A blocked socket sysctl still exits 0, with the reason on stderr and no table.
            guard result.stdout.contains("Proto") else {
                let reason = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
                errors.append(error("netstat -anv -p \(transport) printed no socket table: \(reason.isEmpty ? "empty output" : reason)"))
                continue
            }
            sockets.append(contentsOf: NetstatParser.parse(result.stdout))
        }
        guard !sockets.isEmpty else {
            return DataSourceResult(nodes: [], errors: errors)
        }

        let owners = processOwners(errors: &errors)
        let listeners = Self.makeListeners(
            sockets: sockets,
            owners: owners,
            pathToBundle: NetstatParser.pathToBundleMap(knownApps)
        )
        return DataSourceResult(nodes: listeners, errors: errors)
    }

    private func processOwners(errors: inout [CollectionError]) -> [Int: ProcessOwner] {
        let outcome = runCommand(Self.psPath, ["axo", "pid=,user=,comm="], Shell.defaultTimeoutSeconds)
        guard case .success(let result) = outcome else {
            errors.append(error("ps axo pid=,user=,comm= failed: \(outcome.failureDescription ?? "unknown failure")"))
            return [:]
        }
        return NetstatParser.parseProcessOwners(result.stdout)
    }

    /// Dedupe on `(protocol, address, port, pid)` and attach process ownership.
    static func makeListeners(
        sockets: [NetstatSocket],
        owners: [Int: ProcessOwner],
        pathToBundle: [String: String]
    ) -> [NetworkListener] {
        var seen = Set<String>()
        var listeners: [NetworkListener] = []
        for socket in sockets {
            let key = "\(socket.networkProtocol.rawValue)|\(socket.address)|\(socket.port)|\(socket.pid.map(String.init) ?? "-")"
            guard seen.insert(key).inserted else { continue }
            listeners.append(makeListener(socket, owners: owners, pathToBundle: pathToBundle))
        }
        return listeners
    }

    private static func makeListener(
        _ socket: NetstatSocket,
        owners: [Int: ProcessOwner],
        pathToBundle: [String: String]
    ) -> NetworkListener {
        let owner = socket.pid.flatMap { owners[$0] }
        let processName = owner?.command ?? socket.processName
        let bundleId = owner.flatMap {
            NetstatParser.bundleId(forCommand: $0.command, pathToBundle: pathToBundle)
        }
        return NetworkListener(
            networkProtocol: socket.networkProtocol,
            address: socket.address,
            port: socket.port,
            isLoopback: NetstatParser.isLoopback(socket.address),
            state: socket.networkProtocol == .tcp ? .listen : .bound,
            owner: NetworkListener.Owner(
                pid: socket.pid,
                processName: processName,
                user: owner?.user,
                bundleId: bundleId
            )
        )
    }

    private func error(_ message: String) -> CollectionError {
        CollectionError(source: name, message: message, recoverable: true)
    }
}
