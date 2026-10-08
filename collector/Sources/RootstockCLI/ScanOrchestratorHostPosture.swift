import Foundation
import Models
import HostCommand
import RootstockMacFacts

extension ScanOrchestrator {
    static func collectHostPostureProbeResults() async -> HostPostureProbeResults {
        async let gatekeeperTask = detectGatekeeper()
        async let sipTask = detectSIP()
        async let filevaultTask = detectFileVault()
        async let icloudTask = detectICloudStatus()
        async let hostSettingsTask = detectHostSecuritySettings()
        async let networkConfigurationTask = detectNetworkConfiguration()
        return await HostPostureProbeResults(
            gatekeeper: gatekeeperTask,
            sip: sipTask,
            filevault: filevaultTask,
            icloud: icloudTask,
            hostSettings: hostSettingsTask,
            networkConfiguration: networkConfigurationTask
        )
    }

    /// Returns unknown with a diagnostic if spctl is unavailable or unparseable.
    /// Parsing is shared via `HostPostureProbes` (RootstockMacFacts).
    static func detectGatekeeper(
        runCommand: (String, [String]) -> String? = ScanOrchestrator.runSpctlStatus
    ) -> HostProbeResult {
        guard let output = runCommand(HostPostureProbes.spctlPath, ["--status"]), !output.isEmpty else {
            return HostProbeResult(
                value: nil,
                error: postureError("Gatekeeper probe failed: spctl --status returned no usable output")
            )
        }
        if let value = HostPostureProbes.parseGatekeeperOutput(output) {
            return HostProbeResult(value: value, error: nil)
        }
        return HostProbeResult(
            value: nil,
            error: postureError("Gatekeeper probe returned unrecognized output: \(output)")
        )
    }

    /// `spctl --status` exits non-zero when assessments are disabled, so keep the
    /// output of a non-zero exit when it reports that state.
    static func runSpctlStatus(_ path: String, _ arguments: [String]) -> String? {
        switch Shell.execute(path, arguments) {
        case .success(let result):
            return result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        case .nonZeroExit(let result):
            let output = (result.stdout + result.stderr).trimmingCharacters(in: .whitespacesAndNewlines)
            return output.lowercased().contains("assessments disabled") ? output : nil
        case .admissionTimedOut, .launchFailed, .executionTimedOut:
            return nil
        }
    }

    /// Returns unknown with a diagnostic if csrutil is unavailable or unparseable.
    static func detectSIP(
        runCommand: (String, [String]) -> String? = Shell.run
    ) -> HostProbeResult {
        guard let output = runCommand(HostPostureProbes.csrutilPath, ["status"]), !output.isEmpty else {
            return HostProbeResult(
                value: nil,
                error: postureError("SIP probe failed: csrutil status returned no usable output")
            )
        }
        if let value = HostPostureProbes.parseSIPOutput(output) {
            return HostProbeResult(value: value, error: nil)
        }
        return HostProbeResult(
            value: nil,
            error: postureError("SIP probe returned unrecognized output: \(output)")
        )
    }

    /// Returns unknown with a diagnostic if fdesetup is unavailable or unparseable.
    static func detectFileVault(
        runCommand: (String, [String]) -> String? = Shell.run
    ) -> HostProbeResult {
        guard let output = runCommand(HostPostureProbes.fdesetupPath, ["status"]), !output.isEmpty else {
            return HostProbeResult(
                value: nil,
                error: postureError("FileVault probe failed: fdesetup status returned no usable output")
            )
        }
        if let value = HostPostureProbes.parseFileVaultOutput(output) {
            return HostProbeResult(value: value, error: nil)
        }
        return HostProbeResult(
            value: nil,
            error: postureError("FileVault probe returned unrecognized output: \(output)")
        )
    }

    /// Detect iCloud sign-in, Drive, and Keychain sync status from MobileMeAccounts.plist.
    static func detectICloudStatus(
        readFile: (String) -> Data? = { try? BoundedFileReader.read(path: $0) }
    ) -> ICloudProbeResult {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let plistPath = "\(home)/Library/Preferences/MobileMeAccounts.plist"
        guard let data = readFile(plistPath) else {
            return ICloudProbeResult(
                signedIn: nil,
                driveEnabled: nil,
                keychainEnabled: nil,
                error: postureError("iCloud probe failed: MobileMeAccounts.plist was unavailable or unreadable")
            )
        }
        guard let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let accounts = plist["Accounts"] as? [[String: Any]] else {
            return ICloudProbeResult(
                signedIn: nil,
                driveEnabled: nil,
                keychainEnabled: nil,
                error: postureError("iCloud probe failed: MobileMeAccounts.plist could not be parsed")
            )
        }
        let signedIn = !accounts.isEmpty
        if !signedIn {
            return ICloudProbeResult(
                signedIn: false,
                driveEnabled: false,
                keychainEnabled: false,
                error: nil
            )
        }
        return iCloudServiceStatus(from: accounts)
    }

    private static func iCloudServiceStatus(
        from accounts: [[String: Any]]
    ) -> ICloudProbeResult {
        var driveEnabled = false
        var keychainEnabled = false
        var sawServices = false
        for account in accounts {
            if let services = account["Services"] as? [String: Any] {
                sawServices = true
                if services["MOBILE_DOCUMENTS"] != nil { driveEnabled = true }
                if services["KEYCHAIN_SYNC"] != nil { keychainEnabled = true }
            }
        }
        guard sawServices else {
            return ICloudProbeResult(
                signedIn: true,
                driveEnabled: nil,
                keychainEnabled: nil,
                error: postureError("iCloud probe could not read service sync status; Drive and Keychain posture unknown")
            )
        }
        return ICloudProbeResult(
            signedIn: true,
            driveEnabled: driveEnabled,
            keychainEnabled: keychainEnabled,
            error: nil
        )
    }

    private static func postureError(_ message: String) -> CollectionError {
        CollectionError(source: "Host Posture", message: message, recoverable: true)
    }
}
