/// Compiled AppleScript / OSA delivery residual markers (red↔blue pair).
///
/// Honesty: never compiles malicious .scpt payloads or executes third-party AppleScripts.
public struct OsascriptScptDeliveryParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "OSASCRIPTSCPT", tier: .tier2, description: "OSA/scpt delivery surface markers"),
        fileStem: "osascript_scpt_delivery",
        fieldPrefix: "osa",
        eventType: "osascript.scpt",
        defaultRiskTag: "scpt_surface",
        defaultNotes: "OSA/scpt delivery markers - never compiles malicious .scpt payloads or executes third-party AppleScripts",
        keys: .extended
    )

    public init() {}
}
