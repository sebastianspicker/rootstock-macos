import Foundation
import HostCommand
import Models

extension ScanOrchestrator {
    struct NetworkConfigurationProbeResult {
        let configuration: NetworkConfiguration
        let errors: [CollectionError]
    }

    static let systemConfigurationPreferencesPath = "/Library/Preferences/SystemConfiguration/preferences.plist"
    static let hostsFilePath = "/etc/hosts"
    static let resolvConfPath = "/etc/resolv.conf"

    /// Default `/etc/hosts` entries that are not reported.
    static let defaultHostsEntries: Set<String> = [
        "127.0.0.1 localhost",
        "255.255.255.255 broadcasthost",
        "::1 localhost",
    ]

    /// DNS resolvers, proxies and non-default hosts entries (spec 5.6).
    /// Each failed probe leaves its list empty and adds one recoverable `Host Posture` error.
    static func detectNetworkConfiguration(
        readFile: HostFileReader = readHostFile,
        runCommand: HostCommandRunner = { Shell.execute($0, $1) }
    ) -> NetworkConfigurationProbeResult {
        var errors: [CollectionError] = []
        let dns = detectDNS(readFile: readFile, runCommand: runCommand, errors: &errors)
        let preferences = readPlist(systemConfigurationPreferencesPath, readFile: readFile, errors: &errors)
        let configuration = NetworkConfiguration(
            dnsServers: dns.servers,
            searchDomains: dns.searchDomains,
            proxies: preferences.map(parseProxies) ?? [],
            hostsEntries: detectHostsEntries(readFile: readFile, errors: &errors)
        )
        return NetworkConfigurationProbeResult(configuration: configuration, errors: errors)
    }

    // MARK: - DNS

    struct DNSResolver: Equatable {
        var servers: [String] = []
        var searchDomains: [String] = []
    }

    private static func detectDNS(
        readFile: HostFileReader,
        runCommand: HostCommandRunner,
        errors: inout [CollectionError]
    ) -> DNSResolver {
        let outcome = runCommand("/usr/sbin/scutil", ["--dns"])
        if case .success(let result) = outcome {
            let resolver = parseScutilDNS(result.stdout)
            if !resolver.servers.isEmpty { return resolver }
        }
        if case .data(let data) = readFile(resolvConfPath) {
            let servers = parseResolvConfNameservers(String(decoding: data, as: UTF8.self))
            if !servers.isEmpty { return DNSResolver(servers: servers) }
        }
        errors.append(hostPostureError(
            "DNS probe failed: scutil --dns (\(outcome.failureDescription ?? "no resolver #1 nameservers")) "
                + "and \(resolvConfPath) gave no nameservers"
        ))
        return DNSResolver()
    }

    /// Nameservers and search domains of `resolver #1` in the first `DNS configuration` section.
    static func parseScutilDNS(_ output: String) -> DNSResolver {
        var resolver = DNSResolver()
        var inFirstResolver = false
        for line in output.split(whereSeparator: \.isNewline) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("resolver #") || trimmed.hasPrefix("DNS configuration") {
                if inFirstResolver { break }
                inFirstResolver = trimmed == "resolver #1"
                continue
            }
            guard inFirstResolver, let (key, value) = scutilKeyValue(trimmed) else { continue }
            if key.hasPrefix("nameserver["), !resolver.servers.contains(value) {
                resolver.servers.append(value)
            } else if key.hasPrefix("search domain["), !resolver.searchDomains.contains(value) {
                resolver.searchDomains.append(value)
            }
        }
        return resolver
    }

    private static func scutilKeyValue(_ line: String) -> (String, String)? {
        guard let separator = line.range(of: " : ") else { return nil }
        let key = line[..<separator.lowerBound].trimmingCharacters(in: .whitespaces)
        let value = line[separator.upperBound...].trimmingCharacters(in: .whitespaces)
        return value.isEmpty ? nil : (key, value)
    }

    /// `nameserver` lines of `/etc/resolv.conf`, deduplicated in order.
    static func parseResolvConfNameservers(_ contents: String) -> [String] {
        var servers: [String] = []
        for line in contents.split(whereSeparator: \.isNewline) {
            let tokens = line.split(whereSeparator: \.isWhitespace)
            guard tokens.count >= 2, tokens[0] == "nameserver" else { continue }
            let server = String(tokens[1])
            if !servers.contains(server) { servers.append(server) }
        }
        return servers
    }

    // MARK: - Proxies

    /// Enabled proxies of every network service in `preferences.plist`, ordered by service name.
    static func parseProxies(_ preferences: [String: Any]) -> [ProxySetting] {
        let services = preferences["NetworkServices"] as? [String: Any] ?? [:]
        let named: [(String, [String: Any])] = services.compactMap { serviceId, value in
            guard let service = value as? [String: Any],
                  let proxies = service["Proxies"] as? [String: Any] else { return nil }
            return (service["UserDefinedName"] as? String ?? serviceId, proxies)
        }
        return named.sorted { $0.0 < $1.0 }.flatMap { proxySettings(service: $0.0, proxies: $0.1) }
    }

    static func proxySettings(service: String, proxies: [String: Any]) -> [ProxySetting] {
        let kinds: [(ProxySetting.Kind, String)] = [(.http, "HTTP"), (.https, "HTTPS"), (.socks, "SOCKS")]
        var settings: [ProxySetting] = kinds.compactMap { kind, prefix in
            guard isEnabled(proxies["\(prefix)Enable"]) else { return nil }
            return ProxySetting(
                service: service,
                kind: kind,
                host: proxies["\(prefix)Proxy"] as? String,
                port: (proxies["\(prefix)Port"] as? NSNumber)?.intValue
            )
        }
        if isEnabled(proxies["ProxyAutoConfigEnable"]) {
            settings.append(ProxySetting(
                service: service,
                kind: .pac,
                url: sanitizedPACURL(proxies["ProxyAutoConfigURLString"] as? String)
            ))
        }
        return settings
    }

    /// PAC URL without userinfo, query or fragment (scheme, host, port and path are kept),
    /// so credentials or tokens embedded in the URL are not recorded. Nil when unparseable.
    static func sanitizedPACURL(_ raw: String?) -> String? {
        guard let raw, var components = URLComponents(string: raw), components.scheme != nil else { return nil }
        components.user = nil
        components.password = nil
        components.query = nil
        components.fragment = nil
        return components.string
    }

    private static func isEnabled(_ value: Any?) -> Bool {
        (value as? NSNumber)?.intValue == 1
    }

    // MARK: - /etc/hosts

    private static func detectHostsEntries(
        readFile: HostFileReader,
        errors: inout [CollectionError]
    ) -> [HostsEntry] {
        switch readFile(hostsFilePath) {
        case .absent:
            return []
        case .failed(let message):
            errors.append(hostPostureError("Cannot read \(hostsFilePath): \(message)"))
            return []
        case .data(let data):
            return parseHostsFile(String(decoding: data, as: UTF8.self))
        }
    }

    /// Non-comment `/etc/hosts` lines other than the three macOS defaults.
    static func parseHostsFile(_ contents: String) -> [HostsEntry] {
        contents.split(whereSeparator: \.isNewline).compactMap { line in
            let content = line.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first ?? ""
            let tokens = content.split(whereSeparator: \.isWhitespace).map(String.init)
            guard tokens.count >= 2 else { return nil }
            let hostnames = Array(tokens.dropFirst())
            guard !defaultHostsEntries.contains("\(tokens[0]) \(hostnames.joined(separator: " "))") else {
                return nil
            }
            return HostsEntry(address: tokens[0], hostnames: hostnames)
        }
    }
}
