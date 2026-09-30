public struct PodcastsPathPlaneParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "PODPATH", tier: .tier2, description: "Podcasts path plane markers"),
        fileStem: "podcasts_path_plane",
        fieldPrefix: "podpath",
        eventType: "podcasts.path",
        defaultRiskTag: "podcasts_surface",
        defaultNotes: "Podcasts path plane markers - never dumps podcast episode files or account tokens"
    )

    public init() {}
}
