import Foundation

/// Live host posture snapshot (optional). Offline products may ignore this API.
public struct HostPostureSnapshot: Sendable, Equatable {
    public var gatekeeperEnabled: Bool?
    public var sipEnabled: Bool?
    public var filevaultEnabled: Bool?

    public init(
        gatekeeperEnabled: Bool? = nil,
        sipEnabled: Bool? = nil,
        filevaultEnabled: Bool? = nil
    ) {
        self.gatekeeperEnabled = gatekeeperEnabled
        self.sipEnabled = sipEnabled
        self.filevaultEnabled = filevaultEnabled
    }
}

/// Injectable command runner for tests and product wrappers with timeouts.
public typealias HostPostureCommandRunner = @Sendable (String, [String]) -> String?

/// Read-only probes. Callers map into product models; this kit does not serialize findings.
public enum HostPostureProbes: Sendable {
    public static let spctlPath = "/usr/sbin/spctl"
    public static let csrutilPath = "/usr/bin/csrutil"
    public static let fdesetupPath = "/usr/bin/fdesetup"

    /// Best-effort live snapshot. Returns nils when a probe fails (never throws).
    public static func snapshot(
        run: HostPostureCommandRunner = defaultRunner
    ) -> HostPostureSnapshot {
        HostPostureSnapshot(
            gatekeeperEnabled: probeGatekeeper(run: run),
            sipEnabled: probeSIP(run: run),
            filevaultEnabled: probeFileVault(run: run)
        )
    }

    // MARK: - Pure parsers (shared vocabulary for all products)

    /// Parse `spctl --status` output. Handles "assessments enabled/disabled".
    public static func parseGatekeeperOutput(_ output: String) -> Bool? {
        let lower = output.lowercased()
        if lower.contains("assessments enabled") {
            return true
        }
        if lower.contains("assessments disabled") {
            return false
        }
        // Prefer disabled when both tokens appear in noise.
        if lower.contains("disabled") {
            return false
        }
        if lower.contains("enabled") {
            return true
        }
        return nil
    }

    /// Parse `csrutil status` output.
    public static func parseSIPOutput(_ output: String) -> Bool? {
        let lower = output.lowercased()
        if lower.contains("disabled") {
            return false
        }
        if lower.contains("enabled") {
            return true
        }
        return nil
    }

    /// Parse `fdesetup status` output (incl. deferred enablement).
    public static func parseFileVaultOutput(_ output: String) -> Bool? {
        let lower = output.lowercased()
        let enabledMarkers = [
            "filevault is on",
            "deferred enablement appears to be active"
        ]
        if enabledMarkers.contains(where: lower.contains) {
            return true
        }
        let disabledMarkers = ["filevault is off", "filevault is disabled"]
        if disabledMarkers.contains(where: lower.contains) {
            return false
        }
        return parseFileVaultState(lower)
    }

    private static func parseFileVaultState(_ output: String) -> Bool? {
        guard output.contains("filevault") else { return nil }
        if output.contains(" on") { return true }
        if output.contains(" off") { return false }
        return nil
    }

    /// Map optional bool to IR-style enabled string.
    public static func enabledLabel(_ value: Bool?) -> String {
        switch value {
        case .some(true): return "true"
        case .some(false): return "false"
        case .none: return "unknown"
        }
    }

    // MARK: - Live probes

    public static func probeGatekeeper(run: HostPostureCommandRunner = defaultRunner) -> Bool? {
        guard let output = run(spctlPath, ["--status"]), !output.isEmpty else { return nil }
        return parseGatekeeperOutput(output)
    }

    public static func probeSIP(run: HostPostureCommandRunner = defaultRunner) -> Bool? {
        guard let output = run(csrutilPath, ["status"]), !output.isEmpty else { return nil }
        return parseSIPOutput(output)
    }

    public static func probeFileVault(run: HostPostureCommandRunner = defaultRunner) -> Bool? {
        guard let output = run(fdesetupPath, ["status"]), !output.isEmpty else { return nil }
        return parseFileVaultOutput(output)
    }

    public static let defaultRunner: HostPostureCommandRunner = { launchPath, args in
        runProcess(launchPath, args)
    }

    private static func runProcess(_ launchPath: String, _ args: [String]) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: launchPath)
        process.arguments = args
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return nil
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8)
    }
}
