/// Offline forensic parser: XProtectParser - fixture-backed IR events (no secret export).
import Foundation
import RootstockBlueCore

public struct XProtectParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "XPROTECT",
        tier: .tier1,
        description: "XProtect diagnostic text/logs"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        ArtifactRoot(source: source).enumerate(matching: isXProtectLog).flatMap(parseLog)
    }

    private func isXProtectLog(_ url: URL) -> Bool {
        let name = url.lastPathComponent.lowercased()
        return name.contains("xprotect") && ["diag", "log", "txt"].contains(url.pathExtension)
    }

    private func parseLog(_ file: URL) -> [EventEnvelope] {
        guard let text = try? String(contentsOf: file, encoding: .utf8) else { return [] }
        return text.split(whereSeparator: \.isNewline).compactMap { detectionEvent(from: String($0), file: file) }
    }

    private func detectionEvent(from line: String, file: URL) -> EventEnvelope? {
        guard isDetectionLine(line) else { return nil }
        let malware = extract(after: "detected ", in: line) ?? extract(after: "OSX.", in: line).map { "OSX.\($0)" } ?? "unknown"
        let path = extract(after: "path=", in: line) ?? ""
        return EventEnvelope(identity: EventEnvelope.Identity(kind: "xprotect.detection", label: "XPROTECT"), capture: EventEnvelope.Capture(source: .parser, eventTime: Date(timeIntervalSince1970: 0), collectedAt: Date()), payload: EventEnvelope.Payload(entityRefs: path.isEmpty ? [] : [.file(path: path)], properties: [FieldTaxonomy.xprotectMalware: malware, FieldTaxonomy.filePath: path, "xprotect.line": line, "xprotect.log_path": file.path, FieldTaxonomy.eventType: "xprotect.detection"], provenance: file.path, confidence: 0.75))
    }

    private func isDetectionLine(_ line: String) -> Bool {
        let lower = line.lowercased()
        return lower.contains("xprotect") || lower.contains("malware")
    }

    private func extract(after token: String, in line: String) -> String? {
        guard let r = line.range(of: token, options: .caseInsensitive) else { return nil }
        let rest = line[r.upperBound...]
        let end = rest.firstIndex(where: { $0 == " " || $0 == "\t" }) ?? rest.endIndex
        let value = String(rest[..<end]).trimmingCharacters(in: .whitespaces)
        return value.isEmpty ? nil : value
    }
}
