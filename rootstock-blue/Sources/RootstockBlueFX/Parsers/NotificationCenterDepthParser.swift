public struct NotificationCenterDepthParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "NOTICTR", tier: .tier2, description: "Notification Center depth markers"),
        fileStem: "notification_center_depth",
        fieldPrefix: "notictr",
        eventType: "notification.center",
        defaultRiskTag: "notification_surface",
        defaultNotes: "Notification Center depth markers - never dumps notification body contents or forges notification payloads"
    )

    public init() {}
}
