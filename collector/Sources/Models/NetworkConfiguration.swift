import Foundation

/// Resolver, proxy, and hosts-file configuration of the host.
public struct NetworkConfiguration: Codable, Sendable {
    /// DNS servers of the primary resolver, deduplicated in order.
    public let dnsServers: [String]

    /// Search domains of the primary resolver.
    public let searchDomains: [String]

    /// Enabled proxy settings per network service.
    public let proxies: [ProxySetting]

    /// Non-default `/etc/hosts` entries.
    public let hostsEntries: [HostsEntry]

    public init(
        dnsServers: [String] = [],
        searchDomains: [String] = [],
        proxies: [ProxySetting] = [],
        hostsEntries: [HostsEntry] = []
    ) {
        self.dnsServers = dnsServers
        self.searchDomains = searchDomains
        self.proxies = proxies
        self.hostsEntries = hostsEntries
    }

    enum CodingKeys: String, CodingKey {
        case dnsServers = "dns_servers"
        case searchDomains = "search_domains"
        case proxies
        case hostsEntries = "hosts_entries"
    }
}

/// An enabled proxy configured on a network service.
public struct ProxySetting: Codable, Sendable {
    /// `UserDefinedName` of the network service.
    public let service: String

    /// Proxy kind.
    public let kind: Kind

    /// Proxy host (nil for PAC).
    public let host: String?

    /// Proxy port (nil for PAC).
    public let port: Int?

    /// Proxy auto-configuration URL (PAC only).
    public let url: String?

    public enum Kind: String, Codable, Sendable {
        case http
        case https
        case socks
        case pac
    }

    public init(service: String, kind: Kind, host: String? = nil, port: Int? = nil, url: String? = nil) {
        self.service = service
        self.kind = kind
        self.host = host
        self.port = port
        self.url = url
    }

    enum CodingKeys: String, CodingKey {
        case service
        case kind
        case host
        case port
        case url
    }
}

/// A non-default `/etc/hosts` line.
public struct HostsEntry: Codable, Sendable {
    /// IP address of the entry.
    public let address: String

    /// Host names mapped to the address.
    public let hostnames: [String]

    public init(address: String, hostnames: [String]) {
        self.address = address
        self.hostnames = hostnames
    }

    enum CodingKeys: String, CodingKey {
        case address
        case hostnames
    }
}
