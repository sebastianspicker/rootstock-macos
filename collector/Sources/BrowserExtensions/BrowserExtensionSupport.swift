import Darwin
import Foundation
import HostCommand
import Models

/// Result of listing a directory: absent directories are not errors.
enum DirectoryListing: Sendable {
    case entries([String])
    case absent
    case failed(String)
}

/// Result of a bounded file read: absent files are not errors.
enum FileContents: Sendable {
    case data(Data)
    case absent
    case failed(String)
}

/// Injectable file-system access so the readers stay pure and testable.
struct BrowserFileAccess: Sendable {
    let listDirectory: @Sendable (String) -> DirectoryListing
    let readFile: @Sendable (String, Int) -> FileContents
    /// `lstat` check used to skip symlinked entries inside profile trees.
    var isSymbolicLink: @Sendable (String) -> Bool = { _ in false }

    static let manifestLimit = BoundedFileReader.defaultLimit
    static let preferencesLimit = 16 * 1024 * 1024

    static let live = BrowserFileAccess(
        listDirectory: { path in
            do {
                return .entries(try FileManager.default.contentsOfDirectory(atPath: path).sorted())
            } catch let error as NSError {
                return isMissing(error) ? .absent : .failed(error.localizedDescription)
            }
        },
        readFile: { path, limit in
            var info = stat()
            if stat(path, &info) != 0 {
                let code = errno
                if code == ENOENT || code == ENOTDIR { return .absent }
                return .failed(String(cString: strerror(code)))
            }
            do {
                return .data(try BoundedFileReader.read(path: path, limit: limit))
            } catch {
                return .failed(String(describing: error))
            }
        },
        isSymbolicLink: { SymbolicLinks.isLink(atPath: $0) }
    )

    private static func isMissing(_ error: NSError) -> Bool {
        if error.domain == NSCocoaErrorDomain, error.code == NSFileReadNoSuchFileError || error.code == NSFileNoSuchFileError {
            return true
        }
        guard let underlying = error.userInfo[NSUnderlyingErrorKey] as? NSError,
              underlying.domain == NSPOSIXErrorDomain else { return false }
        return underlying.code == Int(ENOENT) || underlying.code == Int(ENOTDIR)
    }
}

/// Extensions found by one reader plus the recoverable problems it hit.
struct BrowserReadResult {
    var extensions: [BrowserExtension] = []
    var errors: [String] = []

    mutating func append(_ other: BrowserReadResult) {
        extensions.append(contentsOf: other.extensions)
        errors.append(contentsOf: other.errors)
    }
}

/// Shared JSON and timestamp helpers.
enum BrowserExtensionFormat {
    /// Seconds between 1601-01-01 (WebKit/Chromium epoch) and 1970-01-01.
    static let webKitEpochOffset: Double = 11_644_473_600

    static func jsonObject(_ data: Data) -> [String: Any]? {
        (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }

    /// Chromium `install_time`: microseconds since 1601-01-01, stored as a decimal string.
    static func webKitTimeToISO8601(_ value: Any?) -> String? {
        guard let microseconds = number(value), microseconds > 0 else { return nil }
        return iso8601(Date(timeIntervalSince1970: microseconds / 1_000_000 - webKitEpochOffset))
    }

    /// Firefox `installDate`: milliseconds since 1970-01-01.
    static func epochMillisecondsToISO8601(_ value: Any?) -> String? {
        guard let milliseconds = number(value), milliseconds > 0 else { return nil }
        return iso8601(Date(timeIntervalSince1970: milliseconds / 1_000))
    }

    static func iso8601(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: date)
    }

    private static func number(_ value: Any?) -> Double? {
        if let string = value as? String { return Double(string) }
        if let number = value as? NSNumber { return number.doubleValue }
        return nil
    }

    static func strings(_ value: Any?) -> [String] {
        (value as? [Any])?.compactMap { $0 as? String } ?? []
    }

    /// Match patterns (`<all_urls>`, `*://*/*`, `https://…`) belong to host permissions.
    static func isHostPattern(_ permission: String) -> Bool {
        permission == "<all_urls>" || permission.contains("://")
    }
}
