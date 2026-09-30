/// Network share / SMB mount dual-use lateral markers (red↔blue pair).
///
/// Honesty: never mounts attacker shares or writes credentials to NetAuth.
public struct NetworkShareMountParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "NETWORKSHAREMOUNT", tier: .tier2, description: "Network share mount surface markers"),
        fileStem: "network_share_mount",
        fieldPrefix: "share",
        eventType: "network.share_mount",
        defaultRiskTag: "share_surface",
        defaultNotes: "Network share mount markers - never mounts attacker shares or writes credentials to NetAuth",
        keys: .extended
    )

    public init() {}
}
