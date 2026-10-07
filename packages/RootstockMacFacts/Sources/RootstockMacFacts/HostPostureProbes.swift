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

/// Product-owned execution boundary for live posture probes.
///
/// RootstockMacFacts only supplies paths and parsers. Products choose process
/// execution, timeouts, permissions, and output capture before injecting a runner.
public typealias HostPostureCommandRunner = @Sendable (String, [String]) -> String?

/// Neutral posture paths and parsers. Callers map values into product models.
public enum HostPostureProbes: Sendable {
    public static let spctlPath = "/usr/sbin/spctl"
    public static let csrutilPath = "/usr/bin/csrutil"
    public static let fdesetupPath = "/usr/bin/fdesetup"

    /// Parse a best-effort live snapshot supplied by a product-owned runner.
    /// Returns nils when a probe fails or produces unrecognized output.
    public static func snapshot(
        run: HostPostureCommandRunner
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
        parseEnabledState(
            output.lowercased(),
            enabledMarkers: ["assessments enabled", "enabled"],
            disabledMarkers: ["assessments disabled", "disabled"]
        )
    }

    /// Parse `csrutil status` output.
    ///
    /// Only the first non-empty line is classified, so the per-protection
    /// breakdown of a custom configuration ("Apple Internal: disabled", ...)
    /// cannot make the result ambiguous. "enabled (Custom Configuration)" is
    /// reported as enabled.
    public static func parseSIPOutput(_ output: String) -> Bool? {
        let statusLine = output
            .split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .first { !$0.isEmpty } ?? ""
        return parseEnabledState(
            statusLine.lowercased(),
            enabledMarkers: ["enabled"],
            disabledMarkers: ["disabled"]
        )
    }

    /// Parse `fdesetup status` output (incl. deferred enablement).
    public static func parseFileVaultOutput(_ output: String) -> Bool? {
        let lower = output.lowercased()
        let enabledMarkers = [
            "filevault is on",
            "deferred enablement appears to be active"
        ]
        let hasEnabledMarker = enabledMarkers.contains(where: lower.contains)
        let disabledMarkers = ["filevault is off", "filevault is disabled"]
        let hasDisabledMarker = disabledMarkers.contains(where: lower.contains)
        if hasEnabledMarker && hasDisabledMarker { return nil }
        if hasEnabledMarker {
            return true
        }
        if hasDisabledMarker {
            return false
        }
        return parseFileVaultState(lower)
    }

    private static func parseFileVaultState(_ output: String) -> Bool? {
        guard output.contains("filevault") else { return nil }
        let isOn = output.contains(" on")
        let isOff = output.contains(" off")
        if isOn && isOff { return nil }
        if isOn { return true }
        if isOff { return false }
        return nil
    }

    private static func parseEnabledState(
        _ output: String,
        enabledMarkers: [String],
        disabledMarkers: [String]
    ) -> Bool? {
        let isEnabled = enabledMarkers.contains(where: output.contains)
        let isDisabled = disabledMarkers.contains(where: output.contains)
        switch (isEnabled, isDisabled) {
        case (true, false): return true
        case (false, true): return false
        default: return nil
        }
    }

    /// Map optional bool to IR-style enabled string.
    public static func enabledLabel(_ value: Bool?) -> String {
        switch value {
        case .some(true): return "true"
        case .some(false): return "false"
        case .none: return "unknown"
        }
    }

    // MARK: - Product-executed probes

    public static func probeGatekeeper(run: HostPostureCommandRunner) -> Bool? {
        guard let output = run(spctlPath, ["--status"]), !output.isEmpty else { return nil }
        return parseGatekeeperOutput(output)
    }

    public static func probeSIP(run: HostPostureCommandRunner) -> Bool? {
        guard let output = run(csrutilPath, ["status"]), !output.isEmpty else { return nil }
        return parseSIPOutput(output)
    }

    public static func probeFileVault(run: HostPostureCommandRunner) -> Bool? {
        guard let output = run(fdesetupPath, ["status"]), !output.isEmpty else { return nil }
        return parseFileVaultOutput(output)
    }

}
