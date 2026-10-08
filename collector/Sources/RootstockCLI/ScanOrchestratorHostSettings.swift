import Darwin
import Foundation
import HostCommand
import Models

/// Result of a bounded host-file read: absent files are not errors.
enum HostFileRead {
    case data(Data)
    case absent
    case failed(String)
}

typealias HostFileReader = (String) -> HostFileRead
typealias HostCommandRunner = (String, [String]) -> ShellOutcome

extension ScanOrchestrator {
    struct HostSettingsProbeResult {
        let settings: HostSecuritySettings
        let errors: [CollectionError]
    }

    static let loginWindowPlistPath = "/Library/Preferences/com.apple.loginwindow.plist"
    static let softwareUpdatePlistPath = "/Library/Preferences/com.apple.SoftwareUpdate.plist"
    static let commercePlistPath = "/Library/Preferences/com.apple.commerce.plist"
    static let xprotectInfoPath = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
    static let xprotectRemediatorInfoPath = "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist"
    static let mrtInfoPath = "/Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist"

    /// Account, remote administration, update and malware-protection settings (spec 5.5).
    /// Each failed probe leaves its field nil and adds one recoverable `Host Posture` error.
    static func detectHostSecuritySettings(
        readFile: HostFileReader = readHostFile,
        runCommand: HostCommandRunner = { Shell.execute($0, $1) }
    ) -> HostSettingsProbeResult {
        var errors: [CollectionError] = []
        let loginWindow = readPlist(loginWindowPlistPath, readFile: readFile, errors: &errors)
        let accounts = HostSecuritySettings.Accounts(
            guestAccountEnabled: loginWindow?["GuestEnabled"] as? Bool,
            autoLoginUser: loginWindow?["autoLoginUser"] as? String,
            rootAccountEnabled: detectRootAccount(runCommand: runCommand, errors: &errors)
        )
        let malwareProtection = HostSecuritySettings.MalwareProtection(
            xprotectVersion: bundleVersion(xprotectInfoPath, readFile: readFile, errors: &errors),
            xprotectRemediatorVersion: bundleVersion(xprotectRemediatorInfoPath, readFile: readFile, errors: &errors),
            mrtVersion: bundleVersion(mrtInfoPath, readFile: readFile, errors: &errors)
        )
        let settings = HostSecuritySettings(
            accounts: accounts,
            remoteAppleEventsEnabled: detectLaunchdService("com.apple.AEServer", runCommand: runCommand, errors: &errors),
            remoteManagementEnabled: detectLaunchdService(
                "com.apple.RemoteDesktop.agent", runCommand: runCommand, errors: &errors
            ),
            softwareUpdate: detectSoftwareUpdate(readFile: readFile, errors: &errors),
            malwareProtection: malwareProtection
        )
        return HostSettingsProbeResult(settings: settings, errors: errors)
    }

    // MARK: - Root account

    private static func detectRootAccount(
        runCommand: HostCommandRunner,
        errors: inout [CollectionError]
    ) -> Bool? {
        let outcome = runCommand("/usr/bin/dscl", [".", "-read", "/Users/root", "AuthenticationAuthority"])
        let output = outcome.result.map { $0.stdout + "\n" + $0.stderr } ?? ""
        switch outcome {
        case .success, .nonZeroExit:
            if let enabled = rootAccountEnabled(fromDsclOutput: output) {
                return enabled
            }
        case .admissionTimedOut, .launchFailed, .executionTimedOut:
            break
        }
        errors.append(hostPostureError(
            "Root account probe failed: dscl . -read /Users/root AuthenticationAuthority: "
                + (outcome.failureDescription ?? "unrecognized output")
        ))
        return nil
    }

    /// Enabled when an `AuthenticationAuthority` value lacks `;DisabledTags;`; disabled when
    /// the attribute is missing (`No such key`) or carries `;DisabledTags;`; nil otherwise.
    static func rootAccountEnabled(fromDsclOutput output: String) -> Bool? {
        if output.contains("No such key") {
            return false
        }
        guard output.contains("AuthenticationAuthority:") else { return nil }
        return !output.contains(";DisabledTags;")
    }

    // MARK: - launchd services

    private static func detectLaunchdService(
        _ label: String,
        runCommand: HostCommandRunner,
        errors: inout [CollectionError]
    ) -> Bool? {
        let outcome = runCommand("/bin/launchctl", ["print", "system/\(label)"])
        if let loaded = launchdServiceLoaded(outcome) {
            return loaded
        }
        errors.append(hostPostureError(
            "launchctl print system/\(label) failed: \(outcome.failureDescription ?? "unrecognized output")"
        ))
        return nil
    }

    /// Exit 0 → loaded; "Could not find service" → not loaded; anything else → unknown.
    /// A "Bad request." line means launchd refused the query (sandboxed or restricted
    /// caller), so the trailing "Could not find service" text proves nothing.
    static func launchdServiceLoaded(_ outcome: ShellOutcome) -> Bool? {
        switch outcome {
        case .success:
            return true
        case .nonZeroExit(let result):
            let output = result.stdout + result.stderr
            if output.contains("Bad request") { return nil }
            return output.contains("Could not find service") ? false : nil
        case .admissionTimedOut, .launchFailed, .executionTimedOut:
            return nil
        }
    }

    // MARK: - Software Update

    private static func detectSoftwareUpdate(
        readFile: HostFileReader,
        errors: inout [CollectionError]
    ) -> SoftwareUpdateSettings? {
        guard let softwareUpdate = readPlist(softwareUpdatePlistPath, readFile: readFile, errors: &errors) else {
            return nil
        }
        let commerce = readPlist(commercePlistPath, readFile: readFile, errors: &errors)
        return softwareUpdateSettings(softwareUpdate: softwareUpdate, commerce: commerce)
    }

    /// Map `com.apple.SoftwareUpdate` and `com.apple.commerce` preferences to the scan model.
    static func softwareUpdateSettings(
        softwareUpdate: [String: Any],
        commerce: [String: Any]?
    ) -> SoftwareUpdateSettings {
        let configData = softwareUpdate["ConfigDataInstall"] as? Bool
        let critical = softwareUpdate["CriticalUpdateInstall"] as? Bool
        let securityResponses: Bool? = configData == nil && critical == nil
            ? nil
            : (configData ?? true) && (critical ?? true)
        return SoftwareUpdateSettings(
            automaticCheck: softwareUpdate["AutomaticCheckEnabled"] as? Bool ?? true,
            automaticDownload: softwareUpdate["AutomaticDownload"] as? Bool,
            installSecurityResponses: securityResponses,
            installSystemUpdates: softwareUpdate["AutomaticallyInstallMacOSUpdates"] as? Bool,
            installAppUpdates: commerce?["AutoUpdate"] as? Bool,
            lastSuccessfulCheck: (softwareUpdate["LastFullSuccessfulDate"] as? Date).map(iso8601UTC)
        )
    }

    // MARK: - Shared helpers

    private static func bundleVersion(
        _ path: String,
        readFile: HostFileReader,
        errors: inout [CollectionError]
    ) -> String? {
        readPlist(path, readFile: readFile, errors: &errors)?["CFBundleShortVersionString"] as? String
    }

    /// Absent files read as an empty dictionary (every key absent); unreadable or
    /// malformed files return nil with one recoverable error.
    static func readPlist(
        _ path: String,
        readFile: HostFileReader,
        errors: inout [CollectionError]
    ) -> [String: Any]? {
        switch readFile(path) {
        case .absent:
            return [:]
        case .failed(let message):
            errors.append(hostPostureError("Cannot read \(path): \(message)"))
            return nil
        case .data(let data):
            guard let plist = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any] else {
                errors.append(hostPostureError("Cannot parse property list \(path)"))
                return nil
            }
            return plist
        }
    }

    static func readHostFile(_ path: String) -> HostFileRead {
        var info = stat()
        if stat(path, &info) != 0 {
            let code = errno
            if code == ENOENT || code == ENOTDIR { return .absent }
            return .failed(String(cString: strerror(code)))
        }
        do {
            return .data(try BoundedFileReader.read(path: path))
        } catch {
            return .failed(String(describing: error))
        }
    }

    static func iso8601UTC(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: date)
    }

    static func hostPostureError(_ message: String) -> CollectionError {
        CollectionError(source: "Host Posture", message: message, recoverable: true)
    }
}
