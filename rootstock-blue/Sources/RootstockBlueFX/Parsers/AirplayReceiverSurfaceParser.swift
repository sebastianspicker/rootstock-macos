public struct AirplayReceiverSurfaceParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "AIRPLAYRX", tier: .tier2, description: "AirPlay receiver dual-use markers"),
        fileStem: "airplay_receiver_surface",
        fieldPrefix: "airplayrx",
        eventType: "airplay.receiver",
        defaultRiskTag: "airplay_surface",
        defaultNotes: "AirPlay receiver dual-use markers - never enables AirPlay Receiver or spoofs AirPlay targets"
    )

    public init() {}
}
