import Foundation
import Models

/// Serializes a ScanResult to JSON and writes it to disk.
public struct JSONExporter {
    private let encoder: JSONEncoder

    public init() {
        encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    }

    /// Encode a ScanResult to JSON data.
    public func encode(_ result: ScanResult) throws -> Data {
        return try encoder.encode(result)
    }

    /// Write a ScanResult as JSON to the given file path.
    ///
    /// After writing, the output is re-parsed as a sanity check to confirm it is valid JSON.
    public func write(_ result: ScanResult, to path: String) throws {
        let data = try encode(result)
        let url = URL(fileURLWithPath: path)
        try data.write(to: url, options: .atomic)

        // Sanity check: re-parse to confirm the written file is valid JSON.
        guard (try? JSONSerialization.jsonObject(with: data, options: [])) != nil else {
            throw CocoaError(.fileWriteUnknown, userInfo: [
                NSLocalizedDescriptionKey: "Encoded JSON failed to re-parse — output may be corrupt: \(path)"
            ])
        }
    }
}
