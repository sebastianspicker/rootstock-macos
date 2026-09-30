/// Calendar / Reminders automation lateral surface markers (red↔blue pair).
/// Honesty: never reads event contents or creates malicious calendar invites.
public struct CalendarRemindersAutomationParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "CALENDARREMINDERS", tier: .tier2, description: "Calendar/Reminders automation surface markers"),
        fileStem: "calendar_reminders_automation",
        fieldPrefix: "calrem",
        eventType: "calendar.reminders",
        defaultRiskTag: "automation_surface",
        defaultNotes: "Calendar/Reminders automation markers - never reads event contents or creates malicious calendar invites"
    )

    public init() {}
}
