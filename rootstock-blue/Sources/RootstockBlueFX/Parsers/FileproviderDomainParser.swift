public struct FileproviderDomainParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "FPDOM", tier: .tier2, description: "File Provider domain markers"),
        fileStem: "fileprovider_domain",
        fieldPrefix: "fpdom",
        eventType: "fileprovider.domain",
        defaultRiskTag: "fileprovider_surface",
        defaultNotes: "File Provider domain markers - never registers malicious File Provider domains or exfiltrates provider caches"
    )

    public init() {}
}
