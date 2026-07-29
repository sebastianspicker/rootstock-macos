/// CollectionPack - Rootstock product source (see package README for product doctrine).
import Foundation
import RootstockBlueCore

public struct CollectionPack: Codable, Sendable {
    public var name: String
    public var description: String
    public var requiresFDA: Bool
    public var requiresES: Bool
    public var artifacts: [String]

    public init(
        name: String,
        description: String,
        requiresFDA: Bool = true,
        requiresES: Bool = false,
        artifacts: [String]
    ) {
        self.name = name
        self.description = description
        self.requiresFDA = requiresFDA
        self.requiresES = requiresES
        self.artifacts = artifacts
    }

    enum CodingKeys: String, CodingKey {
        case name, description, artifacts
        case requiresFDA = "requires_fda"
        case requiresES = "requires_es"
    }
}

public enum CollectionPackLoader {
    public static func load(from url: URL) throws -> CollectionPack {
        var parser = PackParser(defaultName: url.deletingPathExtension().lastPathComponent)
        for line in try String(contentsOf: url, encoding: .utf8).components(separatedBy: .newlines) {
            parser.consume(line)
        }
        return parser.pack
    }

    private struct PackParser {
        var name: String
        var description = ""
        var requiresFDA = true
        var requiresES = false
        var artifacts: [String] = []
        var inArtifacts = false

        init(defaultName: String) {
            name = defaultName
        }

        var pack: CollectionPack {
            CollectionPack(name: name, description: description, requiresFDA: requiresFDA, requiresES: requiresES, artifacts: artifacts)
        }

        mutating func consume(_ rawLine: String) {
            let line = rawLine.split(separator: "#", maxSplits: 1).first.map(String.init) ?? rawLine
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { return }
            if consumeArtifact(trimmed) { return }
            consumeScalar(trimmed)
        }

        private mutating func consumeArtifact(_ line: String) -> Bool {
            guard line.hasPrefix("- "), inArtifacts else { return false }
            artifacts.append(String(line.dropFirst(2)).trimmingCharacters(in: CharacterSet(charactersIn: "\"")))
            return true
        }

        private mutating func consumeScalar(_ line: String) {
            guard let colon = line.firstIndex(of: ":") else { return }
            let key = String(line[..<colon]).trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespacesAndNewlines).trimmingCharacters(in: CharacterSet(charactersIn: "\""))
            switch key {
            case "name": name = value; inArtifacts = false
            case "description": description = value; inArtifacts = false
            case "requires_fda": requiresFDA = value.lowercased() != "false"; inArtifacts = false
            case "requires_es": requiresES = value.lowercased() == "true"; inArtifacts = false
            case "artifacts": inArtifacts = true
            default: break
            }
        }
    }

    public static func loadDirectory(_ dir: URL) throws -> [CollectionPack] {
        let fm = FileManager.default
        guard let items = try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil) else {
            return []
        }
        return try items
            .filter { $0.pathExtension == "yaml" || $0.pathExtension == "yml" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
            .map { try load(from: $0) }
    }
}
