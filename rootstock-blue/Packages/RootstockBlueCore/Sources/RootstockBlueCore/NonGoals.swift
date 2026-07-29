import Foundation

/// Compile-time documentation of product non-goals.
/// These are not APIs to implement.
public enum NonGoals {
    /// Multi-OS enterprise EDR replacement (Falcon/S1/MDE).
    public static let replaceEnterpriseEDR = false
    /// Break SIP, unsigned kexts, rootkit-style sensors.
    public static let breakSIPOrKexts = false
    /// Secure Enclave / FileVault cryptanalysis.
    public static let crackFileVaultOrSE = false
    /// Silent TCC / FDA bypass.
    public static let silentTCCBypass = false
    /// Become a SIEM or multi-year log lake.
    public static let becomeSIEM = false
    /// Full MDM / device enrollment product.
    public static let becomeMDM = false
    /// Windows/Linux agent parity.
    public static let windowsLinuxParity = false
    /// Physical RAM acquisition on Apple silicon as a product feature.
    public static let physicalRAMAppleSilicon = false
    /// Reimplement Santa allowlist decision engine.
    public static let rewriteSanta = false
    /// AUTH/block mode as default.
    public static let authBlockDefaultOn = false
    /// Packet Tunnel used as fake security VPN / content filter.
    public static let packetTunnelAsFilter = false
    /// Full PCAP capture by default.
    public static let fullPCAPDefault = false
    /// Day-one parity with every mac_apt plugin.
    public static let parseEveryArtifactDayOne = false
    /// Dump keychain secrets / private keys / kcpassword bytes into case export.
    public static let exportKeychainSecrets = false

    public static let messagingForbidden: [String] = [
        "undetectable agent",
        "bypass TCC",
        "defeat SIP",
        "crack FileVault",
        "replace CrowdStrike",
        "AI SOC auto-remediates everything",
        "complete Mac forensics - all artifacts",
    ]
}

/// Product version string for manifests and CLI.
public enum RootstockBlueVersion {
    public static let string = "0.4.0-dfir"
    public static let casePackageFormat = 0
}
