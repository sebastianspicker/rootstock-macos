import Foundation
import Models

/// Reads `com.apple.quarantine` extended attributes from application bundles.
///
/// The quarantine xattr is a semicolon-delimited hex string:
///   `QFLAG;TIMESTAMP;AGENT_BUNDLE_ID;UUID`
///
/// Flags of interest:
///   - 0x0040: User approved (Gatekeeper prompt accepted)
///   - 0x0020: App was translocated (moved to randomised read-only path)
///
/// This data source enriches existing Application objects - it does not discover
/// new applications. It should run after Entitlements and CodeSigning.
public struct QuarantineDataSource {
    public let name = "Quarantine"

    /// The xattr name for quarantine metadata.
    private static let quarantineXattr = "com.apple.quarantine"

    /// Flag bitmask: user approved the quarantined application.
    private static let userApprovedFlag: UInt32 = 0x0040

    /// Flag bitmask: application was translocated.
    private static let translocatedFlag: UInt32 = 0x0020

    public init() {}

    // MARK: - Public API

    /// Enrich an array of applications with quarantine attribute data in place.
    /// Returns the count of applications that have quarantine data.
    public func enrich(applications: inout [Application]) -> Int {
        let (enrichedApps, count) = enriched(applications: applications)
        applications = enrichedApps
        return count
    }

    /// Return a new array of applications enriched with quarantine attribute data.
    /// Uses copy-on-return pattern for safe use with structured concurrency.
    /// Returns the enriched array and the count of quarantined applications.
    public func enriched(applications: [Application]) -> ([Application], Int) {
        let (result, count, _) = enrichedReportingErrors(applications: applications)
        return (result, count)
    }

    /// Like `enriched(applications:)`, but also reports applications whose
    /// quarantine attribute could not be read. Those applications keep
    /// `quarantineInfo == nil` (unknown) instead of claiming "no quarantine flag".
    public func enrichedReportingErrors(
        applications: [Application]
    ) -> ([Application], Int, [CollectionError]) {
        var result = applications
        var count = 0
        var errors: [CollectionError] = []
        for i in result.indices {
            let read = readQuarantineResult(at: result[i].path)
            result[i] = result[i].with(quarantineInfo: read.info)
            if read.info?.hasQuarantineFlag == true {
                count += 1
            }
            if let message = read.error {
                errors.append(CollectionError(
                    source: name,
                    message: "Cannot read quarantine attribute for \(result[i].path): \(message)",
                    recoverable: true
                ))
            }
        }
        return (result, count, errors)
    }

    // MARK: - Quarantine attribute reading

    /// Read and parse the quarantine xattr for the given path.
    /// Returns a QuarantineInfo even if the attribute is absent (hasQuarantineFlag = false).
    public func readQuarantine(at path: String) -> QuarantineInfo {
        readQuarantineResult(at: path).info ?? QuarantineInfo(hasQuarantineFlag: false)
    }

    /// Distinguishes an absent attribute (`info.hasQuarantineFlag == false`) from a
    /// read failure (`info == nil`, `error` set).
    private func readQuarantineResult(at path: String) -> (info: QuarantineInfo?, error: String?) {
        let canonicalPath = URL(fileURLWithPath: path).resolvingSymlinksInPath().path
        let candidates = canonicalPath == path ? [path] : [canonicalPath, path]
        var failure: String?
        for candidate in candidates {
            switch readQuarantineXattr(path: candidate) {
            case .value(let raw):
                return (Self.parseQuarantineString(raw), nil)
            case .absent:
                continue
            case .failed(let message):
                failure = failure ?? message
            }
        }
        if let failure {
            return (nil, failure)
        }
        return (QuarantineInfo(hasQuarantineFlag: false), nil)
    }

    /// Parse the quarantine hex string into structured data.
    ///
    /// Format: `QFLAG;TIMESTAMP;AGENT_BUNDLE_ID;UUID`
    /// Example: `0083;5f3b3c00;com.apple.Safari;12345678-1234-1234-1234-123456789ABC`
    public static func parseQuarantineString(_ raw: String) -> QuarantineInfo {
        let components = raw.split(separator: ";", omittingEmptySubsequences: false).map(String.init)

        // Parse flags (first component, hex)
        var flags: UInt32 = 0
        if let flagStr = components.first {
            flags = UInt32(flagStr, radix: 16) ?? 0
        }

        // Parse timestamp (second component, hex epoch seconds)
        var timestamp: String? = nil
        if components.count > 1 {
            let tsHex = components[1]
            if let epoch = UInt64(tsHex, radix: 16), epoch > 0 {
                let date = Date(timeIntervalSince1970: TimeInterval(epoch))
                let formatter = ISO8601DateFormatter()
                timestamp = formatter.string(from: date)
            }
        }

        // Parse agent bundle ID (third component)
        var agent: String? = nil
        if components.count > 2 {
            let agentStr = components[2].trimmingCharacters(in: .whitespaces)
            if !agentStr.isEmpty {
                agent = agentStr
            }
        }

        let wasUserApproved = (flags & userApprovedFlag) != 0
        let wasTranslocated = (flags & translocatedFlag) != 0

        return QuarantineInfo(
            hasQuarantineFlag: true,
            quarantineAgent: agent,
            quarantineTimestamp: timestamp,
            wasUserApproved: wasUserApproved,
            wasTranslocated: wasTranslocated
        )
    }

    // MARK: - Private

    private enum XattrRead {
        case value(String)
        case absent
        case failed(String)
    }

    /// Read the `com.apple.quarantine` xattr from the given file path.
    /// ENOATTR (and ENOTSUP, for filesystems without xattrs) mean the attribute
    /// is absent; any other error is a failure.
    private func readQuarantineXattr(path: String) -> XattrRead {
        let name = Self.quarantineXattr
        let size = getxattr(path, name, nil, 0, 0, 0)
        if size < 0 {
            return Self.xattrFailure(errno)
        }
        guard size > 0 else { return .absent }

        var buffer = [UInt8](repeating: 0, count: size)
        let result = getxattr(path, name, &buffer, size, 0, 0)
        if result < 0 {
            return Self.xattrFailure(errno)
        }
        guard result > 0 else { return .absent }

        guard let string = String(bytes: buffer[0..<result], encoding: .utf8) else {
            return .failed("attribute value is not valid UTF-8")
        }
        return .value(string)
    }

    private static func xattrFailure(_ code: Int32) -> XattrRead {
        if code == ENOATTR || code == ENOTSUP {
            return .absent
        }
        return .failed("getxattr failed: \(String(cString: strerror(code))) (errno \(code))")
    }
}
