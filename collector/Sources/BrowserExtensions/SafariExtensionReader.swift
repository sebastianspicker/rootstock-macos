import Foundation
import Models

/// Parses Safari extensions from `pluginkit -mAvvv -p <protocol>` output.
///
/// Each block starts with an `identifier(version)` line (optionally prefixed by an
/// election flag such as `+` or `-`) followed by indented `Key = Value` lines.
enum SafariExtensionReader {
    static let bundleId = "com.apple.Safari"
    static let protocols = ["com.apple.Safari.web-extension", "com.apple.Safari.extension"]

    /// One pluginkit record before it is turned into a model.
    struct Block: Equatable {
        var identifier: String
        var version: String
        var path: String = ""
        var displayName: String?
    }

    static func parsePluginkitOutput(_ output: String) -> [BrowserExtension] {
        parseBlocks(output).map(makeExtension)
    }

    static func parseBlocks(_ output: String) -> [Block] {
        var blocks: [Block] = []
        for line in output.split(whereSeparator: \.isNewline).map(String.init) {
            if let (key, value) = keyValue(line) {
                guard !blocks.isEmpty else { continue }
                apply(key: key, value: value, to: &blocks[blocks.count - 1])
            } else if let block = header(line) {
                blocks.append(block)
            }
        }
        return blocks
    }

    private static func keyValue(_ line: String) -> (String, String)? {
        guard let separator = line.range(of: " = ") else { return nil }
        let key = line[..<separator.lowerBound].trimmingCharacters(in: .whitespaces)
        let value = line[separator.upperBound...].trimmingCharacters(in: .whitespaces)
        return (key, value)
    }

    private static func apply(key: String, value: String, to block: inout Block) {
        switch key {
        case "Path": block.path = value
        case "Display Name": block.displayName = value
        case "Version": block.version = value
        default: break
        }
    }

    /// `   +    com.example.Ext(1.2)` → identifier `com.example.Ext`, version `1.2`.
    static func header(_ line: String) -> Block? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
            .drop { "+-=!?".contains($0) }
            .trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, !trimmed.contains(" ") else { return nil }
        guard let open = trimmed.firstIndex(of: "("), trimmed.hasSuffix(")") else {
            return trimmed.contains(".") ? Block(identifier: trimmed, version: "") : nil
        }
        let identifier = String(trimmed[..<open])
        let version = String(trimmed[trimmed.index(after: open)..<trimmed.index(before: trimmed.endIndex)])
        guard identifier.contains(".") else { return nil }
        return Block(identifier: identifier, version: version)
    }

    private static func makeExtension(_ block: Block) -> BrowserExtension {
        BrowserExtension(
            browser: .safari,
            browserBundleId: bundleId,
            profile: "",
            extensionId: block.identifier,
            name: block.displayName ?? block.identifier,
            version: block.version,
            path: block.path
        )
    }
}
