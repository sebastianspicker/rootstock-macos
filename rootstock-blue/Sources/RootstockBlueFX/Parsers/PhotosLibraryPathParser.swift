/// Photos.app library collection path plane markers (red↔blue pair).
/// Honesty: never reads photo contents or exports Photo Library media.
public struct PhotosLibraryPathParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "PHOTOSLIBRARY", tier: .tier2, description: "Photos library path plane markers"),
        fileStem: "photos_library_path",
        fieldPrefix: "photoslib",
        eventType: "photos.library",
        defaultRiskTag: "photos_surface",
        defaultNotes: "Photos library path plane markers - never reads photo contents or exports Photo Library media"
    )

    public init() {}
}
