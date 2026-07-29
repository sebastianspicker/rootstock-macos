import Foundation
import RootstockBlueCore
import RootstockBlueCase

/// Creates a case and optionally materializes an evidence tree into it.
public struct AcquisitionWizard: Sendable {
    public init() {}

    /// Create a destination case and materialize a rooted source tree into its artifacts.
    /// Does not unlock FileVault or bypass FDA.
    public func run(
        outputCase: URL,
        sourceTree: URL? = nil,
        actor: String = NSUserName()
    ) throws -> CasePackage {
        let fileManager = FileManager.default
        try validateDestination(outputCase, fileManager: fileManager)
        let stagedCase = stagingCaseURL(for: outputCase)
        defer { removeUnpublishedStaging(stagedCase, fileManager: fileManager) }
        let package = try createStagedCase(at: stagedCase, outputCase: outputCase)
        try recordAcquisition(package: package, sourceTree: sourceTree, actor: actor)
        try package.updateHashes()
        try validateDestination(outputCase, fileManager: fileManager)
        try fileManager.moveItem(at: stagedCase, to: outputCase)
        return try CasePackage.open(at: outputCase)
    }

    private func validateDestination(_ outputCase: URL, fileManager: FileManager) throws {
        guard !pathEntryExistsOrIsSymlink(outputCase, fileManager: fileManager) else {
            throw RootstockBlueError.caseAlreadyExists(outputCase)
        }
        try fileManager.createDirectory(at: outputCase.deletingLastPathComponent(), withIntermediateDirectories: true)
    }

    private func stagingCaseURL(for outputCase: URL) -> URL {
        outputCase.deletingLastPathComponent().appendingPathComponent(".\(outputCase.lastPathComponent).rootstock-staging-\(UUID().uuidString)", isDirectory: true)
    }

    private func removeUnpublishedStaging(_ stagedCase: URL, fileManager: FileManager) {
        if pathEntryExistsOrIsSymlink(stagedCase, fileManager: fileManager) {
            try? fileManager.removeItem(at: stagedCase)
        }
    }

    private func createStagedCase(at stagedCase: URL, outputCase: URL) throws -> CasePackage {
        try CasePackage.create(at: stagedCase, name: outputCase.deletingPathExtension().lastPathComponent)
    }

    private func recordAcquisition(package: CasePackage, sourceTree: URL?, actor: String) throws {
        guard let sourceTree else {
            try package.appendCustody(CustodyEvent(actor: actor, action: "acquisition_wizard", detail: "Case created without a source tree"))
            return
        }
        let acquisitionRoot = package.rootURL.appendingPathComponent("artifacts/logical_acquire", isDirectory: true)
        let result = try LogicalAcquire.materializeFixtureBundle(from: sourceTree, to: acquisitionRoot, actor: actor)
        try package.appendCustody(CustodyEvent(actor: actor, action: "acquisition_wizard", detail: "Materialized \(result.filesCopied) files from \(sourceTree.path) into logical_acquire (hashes=\(result.custodyHashes.count))"))
    }

    /// Return the acquisition preflight summary.
    public func preflightLines() -> [String] {
        AcquisitionPreflight.report().summaryLines
    }

    private func pathEntryExistsOrIsSymlink(_ url: URL, fileManager: FileManager) -> Bool {
        fileManager.fileExists(atPath: url.path)
            || (try? fileManager.destinationOfSymbolicLink(atPath: url.path)) != nil
    }
}
