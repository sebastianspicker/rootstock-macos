public struct HandoffClipboardDepthParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "HANDOFFCB", tier: .tier2, description: "Handoff clipboard depth markers"),
        fileStem: "handoff_clipboard_depth",
        fieldPrefix: "hdoffcb",
        eventType: "handoff.clipboard",
        defaultRiskTag: "handoff_surface",
        defaultNotes: "Handoff clipboard depth markers - never reads Universal Clipboard contents or forges Handoff activity"
    )

    public init() {}
}
