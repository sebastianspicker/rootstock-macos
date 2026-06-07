import Foundation
import Models

extension ScanOrchestrator {
    static func collectHostPostureProbeResults() async -> HostPostureProbeResults {
        async let gatekeeperTask = detectGatekeeper()
        async let sipTask = detectSIP()
        async let filevaultTask = detectFileVault()
        async let icloudTask = detectICloudStatus()
        return await HostPostureProbeResults(
            gatekeeper: gatekeeperTask,
            sip: sipTask,
            filevault: filevaultTask,
            icloud: icloudTask
        )
    }

    /// Returns unknown with a diagnostic if spctl is unavailable or unparseable.
    static func detectGatekeeper(
        runCommand: (String, [String]) -> String? = Shell.run
    ) -> HostProbeResult {
        guard let output = runCommand("/usr/sbin/spctl", ["--status"]), !output.isEmpty else {
            return HostProbeResult(
                value: nil,
                error: postureError("Gatekeeper probe failed: spctl --status returned no usable output")
            )
        }
        return parseEnabledDisabled(output, subject: "Gatekeeper", enabledWord: "enabled", disabledWord: "disabled")
    }

    /// Returns unknown with a diagnostic if csrutil is unavailable or unparseable.
    static func detectSIP(
        runCommand: (String, [String]) -> String? = Shell.run
    ) -> HostProbeResult {
        guard let output = runCommand("/usr/bin/csrutil", ["status"]), !output.isEmpty else {
            return HostProbeResult(
                value: nil,
                error: postureError("SIP probe failed: csrutil status returned no usable output")
            )
        }
        return parseEnabledDisabled(output, subject: "SIP", enabledWord: "enabled", disabledWord: "disabled")
    }

    /// Returns unknown with a diagnostic if fdesetup is unavailable or unparseable.
    static func detectFileVault(
        runCommand: (String, [String]) -> String? = Shell.run
    ) -> HostProbeResult {
        guard let output = runCommand("/usr/bin/fdesetup", ["status"]), !output.isEmpty else {
            return HostProbeResult(
                value: nil,
                error: postureError("FileVault probe failed: fdesetup status returned no usable output")
            )
        }
        let normalized = output.lowercased()
        if normalized.contains("filevault is on") {
            return HostProbeResult(value: true, error: nil)
        }
        if normalized.contains("filevault is off") || normalized.contains("filevault is disabled") {
            return HostProbeResult(value: false, error: nil)
        }
        return HostProbeResult(
            value: nil,
            error: postureError("FileVault probe returned unrecognized output: \(output)")
        )
    }

    /// Detect iCloud sign-in, Drive, and Keychain sync status from MobileMeAccounts.plist.
    static func detectICloudStatus(
        readFile: (String) -> Data? = { FileManager.default.contents(atPath: $0) }
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

    private static func parseEnabledDisabled(
        _ output: String,
        subject: String,
        enabledWord: String,
        disabledWord: String
    ) -> HostProbeResult {
        let normalized = output.lowercased()
        if normalized.contains(disabledWord) {
            return HostProbeResult(value: false, error: nil)
        }
        if normalized.contains(enabledWord) {
            return HostProbeResult(value: true, error: nil)
        }
        return HostProbeResult(
            value: nil,
            error: postureError("\(subject) probe returned unrecognized output: \(output)")
        )
    }

    private static func postureError(_ message: String) -> CollectionError {
        CollectionError(source: "Host Posture", message: message, recoverable: true)
    }
}
