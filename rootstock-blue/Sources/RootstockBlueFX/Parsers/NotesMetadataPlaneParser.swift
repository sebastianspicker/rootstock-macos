/// Notes.app metadata collection path plane markers (red↔blue pair).
/// Honesty: never reads Notes body contents or exports note secrets.
public struct NotesMetadataPlaneParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "NOTESMETADATA", tier: .tier2, description: "Notes metadata plane markers"),
        fileStem: "notes_metadata_plane",
        fieldPrefix: "notesmeta",
        eventType: "notes.metadata",
        defaultRiskTag: "notes_surface",
        defaultNotes: "Notes metadata plane markers - never reads Notes body contents or exports note secrets"
    )

    public init() {}
}
