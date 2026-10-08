import Foundation
import Models

/// A socket row parsed from `netstat -anv` before process ownership is resolved.
struct NetstatSocket: Equatable, Sendable {
    let networkProtocol: NetworkListener.TransportProtocol
    let address: String
    let port: Int
    let pid: Int?
    /// Process name printed by netstat itself (`process:pid` column on newer macOS).
    let processName: String?
}

/// The owner of a pid as reported by `ps axo pid=,user=,comm=`.
struct ProcessOwner: Equatable, Sendable {
    let user: String
    let command: String
}

/// Pure parsing helpers for `netstat -anv -p tcp|udp` and `ps axo pid=,user=,comm=`.
enum NetstatParser {
    /// Column layout of a `netstat -anv` header, with the two-word address headers merged.
    struct Header: Equatable {
        let pidColumn: Int?
    }

    /// Parse the full netstat output. TCP rows are kept only in `LISTEN` state; all UDP rows are kept.
    static func parse(_ output: String) -> [NetstatSocket] {
        var header: Header?
        var sockets: [NetstatSocket] = []
        for line in output.split(whereSeparator: \.isNewline) {
            let text = String(line)
            if text.hasPrefix("Proto") {
                header = parseHeader(text)
                continue
            }
            if let socket = parseRow(text, header: header) {
                sockets.append(socket)
            }
        }
        return sockets
    }

    /// Locate the pid column (`pid` or `process:pid`) in a header line.
    static func parseHeader(_ line: String) -> Header {
        let merged = line
            .replacingOccurrences(of: "Local Address", with: "Local-Address")
            .replacingOccurrences(of: "Foreign Address", with: "Foreign-Address")
        let columns = merged.split(whereSeparator: \.isWhitespace).map(String.init)
        let pidColumn = columns.firstIndex { $0 == "pid" || $0 == "process:pid" }
        return Header(pidColumn: pidColumn)
    }

    /// Parse one data row; returns nil for headers, non-listening TCP rows, and malformed lines.
    static func parseRow(_ line: String, header: Header?) -> NetstatSocket? {
        let tokens = line.split(whereSeparator: \.isWhitespace).map(String.init)
        guard tokens.count >= 5, let networkProtocol = transportProtocol(tokens[0]) else { return nil }
        let hasState = tokens.count > 5 && isStateToken(tokens[5])
        if networkProtocol == .tcp, !(hasState && tokens[5] == "LISTEN") {
            return nil
        }
        guard let (address, port) = splitAddress(tokens[3]) else { return nil }
        let owner = ownerColumn(tokens: tokens, header: header, hasState: hasState)
        return NetstatSocket(
            networkProtocol: networkProtocol,
            address: address,
            port: port,
            pid: owner.pid,
            processName: owner.processName
        )
    }

    static func transportProtocol(_ token: String) -> NetworkListener.TransportProtocol? {
        let lowered = token.lowercased()
        if lowered.hasPrefix("tcp") { return .tcp }
        if lowered.hasPrefix("udp") { return .udp }
        return nil
    }

    /// Split `addr.port` on the last `.`; `*.*` and non-numeric ports are rejected.
    static func splitAddress(_ token: String) -> (String, Int)? {
        guard let dot = token.lastIndex(of: ".") else { return nil }
        let address = String(token[..<dot])
        guard !address.isEmpty, let port = Int(token[token.index(after: dot)...]) else { return nil }
        return (address, port)
    }

    /// `127.*`, `::1` and `localhost` are loopback; wildcard addresses are not.
    static func isLoopback(_ address: String) -> Bool {
        address.hasPrefix("127.") || address == "::1" || address == "localhost"
    }

    private static func isStateToken(_ token: String) -> Bool {
        !token.isEmpty && token.allSatisfy { $0.isUppercase || $0 == "_" }
    }

    /// Resolve the pid from the `process:pid` form or from the header's pid column.
    /// UDP rows leave the `(state)` column empty, so their tokens sit one column left.
    private static func ownerColumn(
        tokens: [String],
        header: Header?,
        hasState: Bool
    ) -> (pid: Int?, processName: String?) {
        for token in tokens.dropFirst(5) {
            if let owner = processPidToken(token) { return owner }
        }
        guard let pidColumn = header?.pidColumn else { return (nil, nil) }
        let index = hasState ? pidColumn : pidColumn - 1
        guard index > 4, index < tokens.count, let pid = Int(tokens[index]) else { return (nil, nil) }
        return (pid, nil)
    }

    private static func processPidToken(_ token: String) -> (pid: Int?, processName: String?)? {
        guard let colon = token.lastIndex(of: ":") else { return nil }
        let name = String(token[..<colon])
        guard !name.isEmpty, let pid = Int(token[token.index(after: colon)...]) else { return nil }
        return (pid, name)
    }

    /// Parse `ps axo pid=,user=,comm=` into a pid lookup.
    static func parseProcessOwners(_ output: String) -> [Int: ProcessOwner] {
        var owners: [Int: ProcessOwner] = [:]
        for line in output.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
            guard parts.count == 3, let pid = Int(parts[0]) else { continue }
            owners[pid] = ProcessOwner(
                user: String(parts[1]),
                command: parts[2].trimmingCharacters(in: .whitespaces)
            )
        }
        return owners
    }

    /// Resolve a bundle id from a process path with the `.app/` prefix rule.
    static func bundleId(forCommand command: String, pathToBundle: [String: String]) -> String? {
        if let bundleId = pathToBundle[command] { return bundleId }
        guard let appRange = command.range(of: ".app/") else { return nil }
        let appPath = String(command[..<appRange.upperBound].dropLast())
        return pathToBundle[appPath]
    }

    /// Build the application path lookup used by `bundleId(forCommand:pathToBundle:)`.
    static func pathToBundleMap(_ applications: [Application]) -> [String: String] {
        var pathToBundle: [String: String] = [:]
        for app in applications {
            pathToBundle[app.path] = app.bundleId
            let resolvedPath = URL(fileURLWithPath: app.path).resolvingSymlinksInPath().path
            pathToBundle[resolvedPath] = app.bundleId
        }
        return pathToBundle
    }
}
