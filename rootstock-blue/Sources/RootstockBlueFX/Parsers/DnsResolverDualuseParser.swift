/// DNS resolver / mDNSResponder dual-use surface markers (red↔blue pair).
/// Honesty: never rewrites resolver config or poisons DNS caches.
public struct DnsResolverDualuseParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "DNSRESOLVER", tier: .tier2, description: "DNS resolver dual-use markers"),
        fileStem: "dns_resolver_dualuse",
        fieldPrefix: "dnsres",
        eventType: "dns.resolver",
        defaultRiskTag: "dns_surface",
        defaultNotes: "DNS resolver dual-use markers - never rewrites resolver config or poisons DNS caches"
    )

    public init() {}
}
