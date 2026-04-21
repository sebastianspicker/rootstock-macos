import Foundation
import Models

/// Result of the physical security collection pass. Custom struct because a single
/// `system_profiler` call yields both Bluetooth device nodes and host posture properties.
public struct PhysicalSecurityResult {
    public let bluetoothDevices: [BluetoothDevice]
    public let bluetoothEnabled: Bool?
    public let bluetoothDiscoverable: Bool?
    public let lockdownModeEnabled: Bool?
    public let screenLockEnabled: Bool?
    public let screenLockDelay: Int?
    public let displaySleepTimeout: Int?
    public let thunderboltSecurityLevel: String?
    public let secureBootLevel: String?
    public let externalBootAllowed: Bool?
    public let errors: [CollectionError]
}

/// Collects physical security posture: Bluetooth devices & discoverability,
/// Lockdown Mode, screen lock settings, Thunderbolt security, and secure boot status.
public struct PhysicalSecurityDataSource {
    public let name = "Physical Security"
    public let requiresElevation = false

    public init() {}

    /// Collect all physical security data in a single pass.
    public func collectAll() async -> PhysicalSecurityResult {
        var errors: [CollectionError] = []

        // Bluetooth — single system_profiler call for devices + posture
        let (devices, btEnabled, btDiscoverable, btErrors) = collectBluetooth()
        errors.append(contentsOf: btErrors)

        // Lockdown Mode
        let lockdown = detectLockdownMode()

        // Screen lock
        let (screenLock, screenDelay) = collectScreenLock()

        // Display sleep
        let displaySleep = collectDisplaySleep()

        // Thunderbolt security
        let thunderbolt = collectThunderboltSecurity()

        // Secure boot (requires root — degrades gracefully)
        let (secureBoot, externalBoot) = collectSecureBoot()

        return PhysicalSecurityResult(
            bluetoothDevices: devices,
            bluetoothEnabled: btEnabled,
            bluetoothDiscoverable: btDiscoverable,
            lockdownModeEnabled: lockdown,
            screenLockEnabled: screenLock,
            screenLockDelay: screenDelay,
            displaySleepTimeout: displaySleep,
            thunderboltSecurityLevel: thunderbolt,
            secureBootLevel: secureBoot,
            externalBootAllowed: externalBoot,
            errors: errors
        )
    }

    // MARK: - Bluetooth

    func collectBluetooth() -> ([BluetoothDevice], Bool?, Bool?, [CollectionError]) {
        guard let output = Shell.run("/usr/sbin/system_profiler", ["SPBluetoothDataType", "-json"]) else {
            return ([], nil, nil, [
                CollectionError(source: name, message: "system_profiler SPBluetoothDataType failed", recoverable: true)
            ])
        }

        guard let data = output.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return ([], nil, nil, [
                CollectionError(source: name, message: "Failed to parse Bluetooth JSON", recoverable: true)
            ])
        }

        return parseBluetoothJSON(json)
    }

    /// Parse system_profiler SPBluetoothDataType JSON output.
    /// Exposed as internal for testability via `@testable import`.
    func parseBluetoothJSON(_ json: [String: Any]) -> ([BluetoothDevice], Bool?, Bool?, [CollectionError]) {
        guard let items = json["SPBluetoothDataType"] as? [[String: Any]],
              let entry = items.first else {
            return ([], nil, nil, [])
        }

        // Controller state
        var btEnabled: Bool? = nil
        var btDiscoverable: Bool? = nil
        if let controller = entry["controller_properties"] as? [String: Any] {
            if let state = controller["controller_state"] as? String {
                btEnabled = (state == "attrib_on")
            }
            if let disc = controller["controller_discoverable"] as? String {
                btDiscoverable = (disc == "attrib_on")
            }
        }

        // Parse devices from both connected and not-connected arrays
        var devices: [BluetoothDevice] = []
        devices.append(contentsOf: parseDeviceArray(entry["device_connected"], connected: true))
        devices.append(contentsOf: parseDeviceArray(entry["device_not_connected"], connected: false))

        return (devices, btEnabled, btDiscoverable, [])
    }

    private func parseDeviceArray(_ value: Any?, connected: Bool) -> [BluetoothDevice] {
        guard let items = value as? [[String: Any]] else { return [] }
        var devices: [BluetoothDevice] = []
        for item in items {
            // Each item is {deviceName: {device_address: ..., device_minorType: ...}}
            for (deviceName, props) in item {
                guard let propDict = props as? [String: Any],
                      let address = propDict["device_address"] as? String else {
                    continue
                }
                let deviceType = propDict["device_minorType"] as? String ?? "Unknown"
                devices.append(BluetoothDevice(
                    name: deviceName,
                    address: address,
                    deviceType: deviceType,
                    connected: connected
                ))
            }
        }
        return devices
    }

    // MARK: - Lockdown Mode

    func detectLockdownMode() -> Bool? {
        // Try the managed domain first (macOS 16+), then fall back to GlobalPreferences
        if let output = Shell.run("/usr/bin/defaults", ["read", "/Library/Managed Preferences/.GlobalPreferences", "LDMGlobalEnabled"]) {
            return output.trimmingCharacters(in: .whitespacesAndNewlines) == "1"
        }
        if let output = Shell.run("/usr/bin/defaults", ["read", ".GlobalPreferences", "LDMGlobalEnabled"]) {
            return output.trimmingCharacters(in: .whitespacesAndNewlines) == "1"
        }
        return nil
    }

    // MARK: - Screen Lock

    func collectScreenLock() -> (Bool?, Int?) {
        let askForPassword: Bool?
        if let output = Shell.run("/usr/bin/defaults", ["read", "com.apple.screensaver", "askForPassword"]) {
            askForPassword = (output == "1")
        } else {
            askForPassword = nil
        }

        let delay: Int?
        if let output = Shell.run("/usr/bin/defaults", ["read", "com.apple.screensaver", "askForPasswordDelay"]) {
            delay = Int(output)
        } else {
            delay = nil
        }

        return (askForPassword, delay)
    }

    // MARK: - Display Sleep

    func collectDisplaySleep() -> Int? {
        guard let output = Shell.run("/usr/bin/pmset", ["-g", "custom"]) else {
            return nil
        }
        return parseDisplaySleep(output)
    }

    /// Parse `pmset -g custom` output for the displaysleep value.
    /// Exposed as internal for testability.
    func parseDisplaySleep(_ output: String) -> Int? {
        for line in output.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("displaysleep") {
                let parts = trimmed.split(separator: " ")
                if parts.count >= 2, let value = Int(parts.last ?? "") {
                    return value
                }
            }
        }
        return nil
    }

    // MARK: - Thunderbolt Security

    func collectThunderboltSecurity() -> String? {
        guard let output = Shell.run("/usr/sbin/system_profiler", ["SPThunderboltDataType", "-json"]) else {
            return nil
        }

        guard let data = output.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let items = json["SPThunderboltDataType"] as? [[String: Any]],
              let entry = items.first else {
            return nil
        }

        return entry["device_security_level"] as? String
            ?? entry["security_level"] as? String
    }

    // MARK: - Secure Boot

    func collectSecureBoot() -> (String?, Bool?) {
        // bputil -d requires root; degrades to nil for non-root
        guard let output = Shell.run("/usr/sbin/bputil", ["-d"]) else {
            return (nil, nil)
        }
        return parseSecureBootOutput(output)
    }

    /// Parse `bputil -d` output for security level and external boot status.
    /// Exposed as internal for testability.
    func parseSecureBootOutput(_ output: String) -> (String?, Bool?) {
        var level: String? = nil
        var externalBoot: Bool? = nil

        for line in output.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces).lowercased()
            if trimmed.contains("full security") {
                level = "full"
            } else if trimmed.contains("reduced security") {
                level = "reduced"
            } else if trimmed.contains("permissive security") {
                level = "permissive"
            }
            if trimmed.contains("external boot") {
                let isNegated = trimmed.contains("not allowed") || trimmed.contains("disallowed") || trimmed.contains("false")
                let isAllowed = trimmed.contains("allowed") || trimmed.contains("true")
                externalBoot = isAllowed && !isNegated
            }
        }

        return (level, externalBoot)
    }
}
