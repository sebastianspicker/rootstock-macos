/// PAM authentication module residual surface markers (red↔blue pair).
/// Honesty: never installs PAM modules or modifies /etc/pam.d.
public struct PamAuthModuleParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "PAMAUTHMODULE", tier: .tier2, description: "PAM auth module surface markers"),
        fileStem: "pam_auth_module",
        fieldPrefix: "pammod",
        eventType: "pam.module",
        defaultRiskTag: "pam_surface",
        defaultNotes: "PAM auth module surface markers - never installs PAM modules or modifies /etc/pam.d"
    )

    public init() {}
}
