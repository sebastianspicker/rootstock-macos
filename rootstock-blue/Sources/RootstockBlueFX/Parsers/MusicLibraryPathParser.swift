public struct MusicLibraryPathParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "MUSLIB", tier: .tier2, description: "Music library path markers"),
        fileStem: "music_library_path",
        fieldPrefix: "muslib",
        eventType: "music.library",
        defaultRiskTag: "music_surface",
        defaultNotes: "Music library path markers - never exports Music library media or DRM material"
    )

    public init() {}
}
