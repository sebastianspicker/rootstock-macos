public struct FindmyPathPlaneParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "FMPATH", tier: .tier2, description: "Find My path plane markers"),
        fileStem: "findmy_path_plane",
        fieldPrefix: "fmpath",
        eventType: "findmy.path",
        defaultRiskTag: "findmy_surface",
        defaultNotes: "Find My path plane markers - never queries Find My device locations or dumps owner tokens"
    )

    public init() {}
}
