public struct RemindersCloudPathParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "REMCLOUD", tier: .tier2, description: "Reminders cloud path markers"),
        fileStem: "reminders_cloud_path",
        fieldPrefix: "remcloud",
        eventType: "reminders.cloud",
        defaultRiskTag: "reminders_cloud_surface",
        defaultNotes: "Reminders cloud path markers - never reads reminder titles/bodies or exports Reminders databases"
    )

    public init() {}
}
