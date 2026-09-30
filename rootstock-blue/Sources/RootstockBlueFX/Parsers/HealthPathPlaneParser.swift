public struct HealthPathPlaneParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "HLTHPATH", tier: .tier2, description: "Health path plane markers"),
        fileStem: "health_path_plane",
        fieldPrefix: "hlthpath",
        eventType: "health.path",
        defaultRiskTag: "health_surface",
        defaultNotes: "Health path plane markers - never exports HealthKit samples or medical records"
    )

    public init() {}
}
