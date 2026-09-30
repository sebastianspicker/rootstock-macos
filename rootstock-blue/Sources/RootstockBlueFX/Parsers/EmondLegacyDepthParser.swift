/// Emond legacy rules residual depth markers (red↔blue pair).
/// Honesty: never installs emond rules or enables the legacy event monitor daemon.
public struct EmondLegacyDepthParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "EMONDLEGACY", tier: .tier2, description: "Emond legacy depth markers"),
        fileStem: "emond_legacy_depth",
        fieldPrefix: "emondleg",
        eventType: "emond.legacy",
        defaultRiskTag: "emond_surface",
        defaultNotes: "Emond legacy depth markers - never installs emond rules or enables the legacy event monitor daemon"
    )

    public init() {}
}
