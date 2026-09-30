public struct MapsLocationPathParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "MAPSLOC", tier: .tier2, description: "Maps location residual markers"),
        fileStem: "maps_location_path",
        fieldPrefix: "mapsloc",
        eventType: "maps.location",
        defaultRiskTag: "maps_location_surface",
        defaultNotes: "Maps location residual markers - never dumps location history or spoofs CoreLocation positions"
    )

    public init() {}
}
