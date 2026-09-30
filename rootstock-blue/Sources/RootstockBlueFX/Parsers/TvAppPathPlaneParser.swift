public struct TvAppPathPlaneParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "TVPATH", tier: .tier2, description: "TV.app path plane markers"),
        fileStem: "tv_app_path_plane",
        fieldPrefix: "tvpath",
        eventType: "tv.path",
        defaultRiskTag: "tv_surface",
        defaultNotes: "TV.app path plane markers - never dumps TV.app media caches or account material"
    )

    public init() {}
}
