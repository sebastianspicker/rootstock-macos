import Foundation
import RootstockBlueCore
import RootstockBlueCase

/// Interchange entry points for external collection formats.
public enum Interchange {
    public struct ImportResult: Sendable {
        public var extractedFiles: Int
        public var parsedEvents: Int
        public var rootURL: URL
    }

    private static let zipImportDisabledMessage =
        "ZIP archive import is disabled in this alpha. Parse an already-extracted artifact tree with parse."

    /// ZIP archive import is unavailable in this alpha.
    public static func importCollectionZip(
        at zipURL: URL,
        into package: CasePackage,
        actor: String = NSUserName()
    ) throws -> ImportResult {
        _ = (zipURL, package, actor)
        throw RootstockBlueError.notImplemented(zipImportDisabledMessage)
    }

    public static func importVelociraptorZip(at url: URL, into package: CasePackage) throws -> ImportResult {
        try importCollectionZip(at: url, into: package)
    }

    public static func importUACArchive(at url: URL, into package: CasePackage) throws -> ImportResult {
        try importCollectionZip(at: url, into: package)
    }

    /// Legacy entry point retained for API compatibility.
    public static func importVelociraptorZip(at url: URL) throws {
        _ = url
        throw RootstockBlueError.notImplemented(zipImportDisabledMessage)
    }

    public static func importUACArchive(at url: URL) throws {
        _ = url
        throw RootstockBlueError.notImplemented(zipImportDisabledMessage)
    }
}
