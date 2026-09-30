public struct WalletPassPathParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "WLTPASS", tier: .tier2, description: "Wallet pass path markers"),
        fileStem: "wallet_pass_path",
        fieldPrefix: "wltpass",
        eventType: "wallet.pass",
        defaultRiskTag: "wallet_surface",
        defaultNotes: "Wallet pass path markers - never dumps pass contents, payment tokens, or card data"
    )

    public init() {}
}
