import Foundation
import HostCommand
import Models

/// Lists installer package receipts from `/var/db/receipts/*.plist`.
public struct InstalledPackagesDataSource: DataSource {
    public let name = "Installed Packages"
    public let requiresElevation = false

    static let maxReceipts = 5000

    private let receiptsDirectory: String

    public init(receiptsDirectory: String = "/var/db/receipts") {
        self.receiptsDirectory = receiptsDirectory
    }

    public func collect() async -> DataSourceResult {
        let names: [String]
        do {
            names = try FileManager.default.contentsOfDirectory(atPath: receiptsDirectory)
                .filter { $0.hasSuffix(".plist") }
                .sorted()
        } catch {
            return DataSourceResult(nodes: [], errors: [failure(
                "Cannot list \(receiptsDirectory): \(error.localizedDescription)"
            )])
        }

        var errors: [CollectionError] = []
        if names.count > Self.maxReceipts {
            errors.append(failure("Receipt inventory truncated to \(Self.maxReceipts) of \(names.count) receipts"))
        }
        var packages: [InstalledPackage] = []
        for fileName in names.prefix(Self.maxReceipts) {
            let path = "\(receiptsDirectory)/\(fileName)"
            do {
                let data = try BoundedFileReader.read(path: path)
                guard let package = Self.parseReceipt(data, fileName: fileName) else {
                    errors.append(failure("Malformed receipt plist \(path)"))
                    continue
                }
                packages.append(package)
            } catch {
                errors.append(failure("Cannot read receipt \(path): \(error)"))
            }
        }
        packages.sort { $0.packageId < $1.packageId }
        return DataSourceResult(nodes: packages, errors: errors)
    }

    /// Parse one receipt plist; `PackageIdentifier` falls back to the file basename.
    static func parseReceipt(_ data: Data, fileName: String) -> InstalledPackage? {
        guard let plist = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any] else {
            return nil
        }
        let fallbackId = fileName.hasSuffix(".plist") ? String(fileName.dropLast(6)) : fileName
        return InstalledPackage(
            packageId: nonEmpty(plist["PackageIdentifier"]) ?? fallbackId,
            version: nonEmpty(plist["PackageVersion"]),
            installDate: (plist["InstallDate"] as? Date).map(iso8601),
            installPrefix: nonEmpty(plist["InstallPrefixPath"]),
            installProcess: nonEmpty(plist["InstallProcessName"]),
            packageFileName: nonEmpty(plist["PackageFileName"])
        )
    }

    private static func nonEmpty(_ value: Any?) -> String? {
        guard let string = value as? String, !string.isEmpty else { return nil }
        return string
    }

    static func iso8601(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: date)
    }

    private func failure(_ message: String) -> CollectionError {
        CollectionError(source: name, message: message, recoverable: true)
    }
}
