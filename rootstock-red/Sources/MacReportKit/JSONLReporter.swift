/// JSONLReporter - Rootstock product source (see package README for product doctrine).
import Foundation
import RootstockCore

public enum JSONLReporter {
    public static func render(_ findings: [Finding]) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        var lines: [String] = []
        for finding in findings {
            let data = try encoder.encode(finding)
            guard let line = String(data: data, encoding: .utf8) else {
                throw RootstockError.io("failed to encode finding \(finding.id)")
            }
            lines.append(line)
        }
        return (lines.joined(separator: "\n") + (lines.isEmpty ? "" : "\n")).data(using: .utf8) ?? Data()
    }

    public static func renderArray(_ findings: [Finding]) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(findings)
    }
}
