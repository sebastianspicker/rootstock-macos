public struct CalendarServerPathParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "CALDAV", tier: .tier2, description: "Calendar CalDAV residual markers"),
        fileStem: "calendar_server_path",
        fieldPrefix: "caldav",
        eventType: "calendar.caldav",
        defaultRiskTag: "caldav_surface",
        defaultNotes: "Calendar CalDAV residual markers - never reads calendar event bodies or credentials from CalDAV stores"
    )

    public init() {}
}
