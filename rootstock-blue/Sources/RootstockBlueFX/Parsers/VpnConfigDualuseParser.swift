/// VPN configuration dual-use residual surface markers (red↔blue pair).
/// Honesty: never installs VPN profiles or rewrites network extension VPN configs.
public struct VpnConfigDualuseParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "VPNCONFIGDUAL", tier: .tier2, description: "VPN config dual-use markers"),
        fileStem: "vpn_config_dualuse",
        fieldPrefix: "vpncfg",
        eventType: "vpn.config",
        defaultRiskTag: "vpn_surface",
        defaultNotes: "VPN config dual-use markers - never installs VPN profiles or rewrites network extension VPN configs"
    )

    public init() {}
}
