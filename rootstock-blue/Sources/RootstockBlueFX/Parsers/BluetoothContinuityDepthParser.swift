/// Bluetooth / Continuity proximity residual depth markers (red↔blue pair).
/// Honesty: never enables Bluetooth pairing or spoofs Continuity identities.
public struct BluetoothContinuityDepthParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "BTCONTINUITY", tier: .tier2, description: "Bluetooth Continuity depth markers"),
        fileStem: "bluetooth_continuity_depth",
        fieldPrefix: "btcont",
        eventType: "bluetooth.continuity",
        defaultRiskTag: "bt_continuity_surface",
        defaultNotes: "Bluetooth Continuity depth markers - never enables Bluetooth pairing or spoofs Continuity identities"
    )

    public init() {}
}
