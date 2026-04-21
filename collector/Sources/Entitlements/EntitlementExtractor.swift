import Foundation
import Security
import os.log

/// Extracts the entitlements dictionary from a signed executable.
///
/// Primary method: Security.framework `SecCodeCopySigningInformation`
/// Fallback: `codesign -d --entitlements :- <path>` CLI output parsed as plist
public struct EntitlementExtractor {

    private static let logger = Logger(subsystem: "com.rootstock.collector", category: "EntitlementExtractor")

    public init() { }

    /// Returns an empty dictionary if extraction fails.
    public func extract(from executableURL: URL) -> [String: Any] {
        if let result = extractWithSecurityFramework(url: executableURL) {
            return result
        }
        Self.logger.debug("Security.framework extraction failed for \(executableURL.path, privacy: .public), falling back to codesign CLI")
        return extractWithCodesignCLI(path: executableURL.path) ?? [:]
    }

    // MARK: - Security.framework (primary)

    private func extractWithSecurityFramework(url: URL) -> [String: Any]? {
        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(
            url as CFURL, SecCSFlags(rawValue: 0), &staticCode
        )
        guard createStatus == errSecSuccess, let code = staticCode else {
            Self.logger.debug("SecStaticCodeCreateWithPath failed (status \(createStatus)) for \(url.path, privacy: .public)")
            return nil
        }

        // Swift bridges SecCodeCopySigningInformation to take SecStaticCode directly.
        // kSecCSSigningInformation (0x2) makes kSecCodeInfoEntitlementsDict available.
        var cfInfo: CFDictionary?
        let copyStatus = SecCodeCopySigningInformation(code, SecCSFlags(rawValue: 0x2), &cfInfo)
        guard copyStatus == errSecSuccess,
              let info = cfInfo as? [String: Any] else {
            Self.logger.debug("SecCodeCopySigningInformation failed (status \(copyStatus)) for \(url.path, privacy: .public)")
            return nil
        }

        return info[kSecCodeInfoEntitlementsDict as String] as? [String: Any]
    }

    // MARK: - codesign CLI (fallback)

    private func extractWithCodesignCLI(path: String) -> [String: Any]? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        // `:- ` = write to stdout in plist/XML format
        process.arguments = ["-d", "--entitlements", ":-", path]

        let stdoutPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = Pipe()  // discard stderr

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return nil
        }

        let data = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        guard !data.isEmpty else { return nil }

        var format = PropertyListSerialization.PropertyListFormat.xml
        return try? PropertyListSerialization.propertyList(
            from: data, options: [], format: &format
        ) as? [String: Any]
    }
}
