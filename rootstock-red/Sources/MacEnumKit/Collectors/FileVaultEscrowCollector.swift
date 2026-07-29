import Foundation
import RootstockCore

/// FileVault / recovery escrow posture (Wave-7).
///
/// Research basis: PEASS FV status; MDM recovery escrow research.
/// Safety and behavior: typed `FileVaultEscrowState`; escrow paths only - never recovery keys or unlock recipes.
public struct FileVaultEscrowCollector: Collector {
    public static let id = "collect.filevault_escrow"
    public static let cost: CollectorCost = .low

    private static let escrowPathHints: [String] = [
        "/Library/Preferences/com.apple.security.FDERecoveryKeyEscrow.plist",
        "/Library/Preferences/com.apple.MCX.FileVaultSettings.plist",
        "/Library/Preferences/com.apple.security.FDE.plist",
        "/var/db/ConfigurationProfiles",
        "/Library/Keychains/FileVaultMaster.keychain",
        "/System/Library/CoreServices/SecurityAgentPlugins/DiskUnlock.bundle",
    ]

    private static let institutionalEscrowHints: [String] = [
        "/Library/Preferences/com.apple.security.FDERecoveryKeyEscrow.plist",
        "/Library/Managed Preferences",
        "/var/db/ConfigurationProfiles/Settings",
        "/Library/Application Support/JAMF",
        "/Library/Application Support/Microsoft/Intune",
        "/Library/Application Support/com.apple.mdmclient",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "FileVault/escrow surface: status class + path presence - NEVER recovery-key material",
        ]

        let fdesetupPath = "/usr/bin/fdesetup"
        let fdesetupPresent = fm.fileExists(atPath: fdesetupPath)
        if fdesetupPresent {
            notes.append("fdesetup_present: \(fdesetupPath) (not invoked for keys)")
        } else {
            notes.append("fdesetup not observed at \(fdesetupPath)")
        }

        // Optional non-mutating status probe via allowlisted ProcessRunner if available,
        // prefer path heuristics to stay deny-safe and key-free. Mirror protections when present.
        let fileVaultOn: Bool? = nil
        // Read-only: check for APFS encryption-related support paths as weak signal only.
        let cryptoSupport = [
            "/System/Library/LaunchDaemons/com.apple.securekeybackupd.plist",
            "/usr/libexec/securekeybackupd",
        ]
        for path in cryptoSupport where fm.fileExists(atPath: path) {
                notes.append("crypto_support: \(path)")
        }

        var escrow: [String] = []
        for path in Self.escrowPathHints where fm.fileExists(atPath: path) {
                escrow.append(path)
                notes.append("escrow_path_hint: \(path)")
        }

        var institutional: [String] = []
        for path in Self.institutionalEscrowHints where fm.fileExists(atPath: path) {
                institutional.append(path)
                notes.append("institutional_escrow_hint: \(path)")
        }

        escrow = Array(Set(escrow)).sorted()
        institutional = Array(Set(institutional)).sorted()

        // If FileVaultMaster keychain exists, FV institutional escrow class is more likely,
        // still never opens keychain.
        if escrow.contains(where: { $0.contains("FileVaultMaster") }) {
            notes.append("FileVaultMaster.keychain path observed (not opened; no key dump)")
        }

        var state = CollectedState()
        state.fileVaultEscrow = FileVaultEscrowState(
            fileVaultOn: fileVaultOn,
            escrowPathHints: escrow,
            institutionalEscrowHints: institutional,
            fdesetupPresent: fdesetupPresent,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "fv=\(fileVaultOn.map(String.init(describing:)) ?? "unknown") "
            + "escrowPaths=\(escrow.count) institutional=\(institutional.count) "
            + "fdesetup=\(fdesetupPresent)"
        return state
    }
}
