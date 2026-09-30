public struct SiriSuggestionsPlaneParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "SIRISUG", tier: .tier2, description: "Siri Suggestions residual markers"),
        fileStem: "siri_suggestions_plane",
        fieldPrefix: "sirisug",
        eventType: "siri.suggestions",
        defaultRiskTag: "siri_surface",
        defaultNotes: "Siri Suggestions residual markers - never dumps Siri transcripts or Suggestions databases contents"
    )

    public init() {}
}
