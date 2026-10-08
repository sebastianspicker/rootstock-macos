import Foundation
import HostCommand

/// Stable identity of the scanned Mac, so scans of two Macs that share a hostname stay apart.
enum HardwareIdentity {
    static let ioregPath = "/usr/sbin/ioreg"
    static let ioregArguments = ["-rd1", "-c", "IOPlatformExpertDevice"]

    /// `IOPlatformUUID` from ioreg; nil when ioreg fails or prints no UUID.
    static func detect() -> String? {
        guard case .success(let result) = Shell.execute(ioregPath, ioregArguments, timeoutSeconds: 5) else {
            return nil
        }
        return parseIOPlatformUUID(result.stdout)
    }

    /// Value of the `"IOPlatformUUID" = "…"` line, accepted only when it is a UUID.
    static func parseIOPlatformUUID(_ output: String) -> String? {
        for line in output.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: "=", maxSplits: 1)
            guard parts.count == 2,
                  parts[0].trimmingCharacters(in: .whitespaces) == "\"IOPlatformUUID\"" else { continue }
            let value = parts[1].trimmingCharacters(in: .whitespaces)
            guard value.count >= 2, value.hasPrefix("\""), value.hasSuffix("\"") else { return nil }
            return UUID(uuidString: String(value.dropFirst().dropLast()))?.uuidString
        }
        return nil
    }
}
