public struct ImessagePathPlaneParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "IMSGPATH", tier: .tier2, description: "iMessage path plane markers"),
        fileStem: "imessage_path_plane",
        fieldPrefix: "imsgpath",
        eventType: "imessage.path",
        defaultRiskTag: "imessage_surface",
        defaultNotes: "iMessage path plane markers - never reads Messages database contents or exports chat transcripts"
    )

    public init() {}
}
