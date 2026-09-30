import Foundation
import RootstockBlueCore

/// Honest acquisition capability report - documents what logical acquire CAN and CANNOT do.
public struct AcquisitionPreflight: Sendable {
    public struct Capability: Sendable, Equatable {
        public var name: String
        public var available: Bool
        public var detail: String

        public init(name: String, available: Bool, detail: String) {
            self.name = name
            self.available = available
            self.detail = detail
        }
    }

    public var capabilities: [Capability]
    public var nonGoals: [String]

    public init(capabilities: [Capability], nonGoals: [String]) {
        self.capabilities = capabilities
        self.nonGoals = nonGoals
    }

    /// Static honesty report (no privilege escalation, no FV crack).
    public static func report() -> AcquisitionPreflight {
        AcquisitionPreflight(
            capabilities: [
                Capability(
                    name: "Logical tree copy",
                    available: true,
                    detail: "Can copy a rooted evidence tree / fixture bundle into a case-friendly package with custody hashes"
                ),
                Capability(
                    name: "Offline parse of copied tree",
                    available: true,
                    detail: "RootstockBlueFX ForensicsEngine can parse after materialize (separate step)"
                ),
                Capability(
                    name: "Full Disk Access (FDA)",
                    available: false,
                    detail: "Cannot grant FDA; live host collection of protected paths requires operator-granted FDA"
                ),
                Capability(
                    name: "FileVault unlock",
                    available: false,
                    detail: "Cannot unlock or crack FileVault; requires user/org credentials (secretsRequired)"
                ),
                Capability(
                    name: "Secure Enclave secrets",
                    available: false,
                    detail: "No SE key extraction or biometric theft path"
                ),
                Capability(
                    name: "Physical / RAM acquisition",
                    available: false,
                    detail: "Not a product goal on Apple silicon (see NonGoals)"
                ),
            ],
            nonGoals: [
                "Crack FileVault or Secure Enclave",
                "Bypass TCC / FDA silently",
                "Replace commercial imagers (Fuji/ASLA) for bit-for-bit disk images",
                "Silent remote implant-style collection",
            ]
        )
    }

    public var summaryLines: [String] {
        var lines: [String] = ["acquisition_preflight:"]
        for c in capabilities {
            let mark = c.available ? "can" : "cannot"
            lines.append("  [\(mark)] \(c.name): \(c.detail)")
        }
        lines.append("non_goals:")
        for n in nonGoals {
            lines.append("  - \(n)")
        }
        return lines
    }
}
