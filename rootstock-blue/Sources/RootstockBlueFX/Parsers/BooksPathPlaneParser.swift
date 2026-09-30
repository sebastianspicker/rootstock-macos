public struct BooksPathPlaneParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "BKPATH", tier: .tier2, description: "Books path plane markers"),
        fileStem: "books_path_plane",
        fieldPrefix: "bkpath",
        eventType: "books.path",
        defaultRiskTag: "books_surface",
        defaultNotes: "Books path plane markers - never extracts EPUB contents or Books annotations as bulk export"
    )

    public init() {}
}
