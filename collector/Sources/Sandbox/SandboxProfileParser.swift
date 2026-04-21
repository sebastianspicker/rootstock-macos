import Foundation

/// Parses sandbox profile text (SBPL — Sandbox Profile Language) into
/// structured rules grouped by category.
///
/// SBPL profiles use a Scheme-like syntax with `(allow ...)` and `(deny ...)`
/// directives. This parser extracts the top-level directives and groups them
/// into: file-read, file-write, mach-lookup, network, and iokit categories.
///
/// Example SBPL:
///   (allow file-read* (subpath "/usr/share"))
///   (allow mach-lookup (global-name "com.apple.SecurityServer"))
///   (deny network-outbound)
public struct SandboxProfileParser {

    /// A parsed sandbox rule.
    public struct Rule {
        public let action: String    // "allow" or "deny"
        public let operation: String // e.g. "file-read*", "mach-lookup"
        public let filter: String    // the rest of the directive, or ""
    }

    /// Parse raw SBPL text into categorized string arrays.
    public func parse(_ profileText: String) -> CategorizedRules {
        let rules = extractRules(from: profileText)
        return categorize(rules)
    }

    /// Result of categorizing sandbox rules.
    public struct CategorizedRules {
        public var fileReadRules: [String] = []
        public var fileWriteRules: [String] = []
        public var machLookupRules: [String] = []
        public var networkRules: [String] = []
        public var iokitRules: [String] = []
    }

    // MARK: - Extraction

    /// Extract top-level `(allow ...)` and `(deny ...)` directives from SBPL text.
    func extractRules(from text: String) -> [Rule] {
        var rules: [Rule] = []

        // Match (allow|deny <operation> ...) patterns.
        // The regex captures: action, operation, and optional filter text.
        // NOTE: This regex uses a non-greedy match for the filter body and
        // does not handle arbitrarily nested parentheses. SBPL directives
        // with deeply nested sub-expressions (e.g. nested `require-any` /
        // `require-all`) may only capture partial filter text. A full
        // recursive-descent parser would be needed for complete accuracy,
        // but the current approach is sufficient for extracting the
        // operation type and top-level filter for categorization purposes.
        let pattern = #"\((allow|deny)\s+([\w\-\*]+)(?:\s+((?:[^()]*|\((?:[^()]*|\([^()]*\))*\))*)?)?\)"#
        guard let regex = try? NSRegularExpression(pattern: pattern, options: []) else {
            return rules
        }

        let nsText = text as NSString
        let matches = regex.matches(in: text, options: [], range: NSRange(location: 0, length: nsText.length))

        for match in matches {
            let action = nsText.substring(with: match.range(at: 1))
            let operation = nsText.substring(with: match.range(at: 2))
            let filter: String
            if match.range(at: 3).location != NSNotFound {
                filter = nsText.substring(with: match.range(at: 3))
            } else {
                filter = ""
            }
            rules.append(Rule(action: action, operation: operation, filter: filter))
        }

        return rules
    }

    /// Categorize parsed rules by operation prefix.
    func categorize(_ rules: [Rule]) -> CategorizedRules {
        var result = CategorizedRules()

        for rule in rules {
            let display = formatRule(rule)
            let op = rule.operation.lowercased()

            if op.hasPrefix("file-read") {
                result.fileReadRules.append(display)
            } else if op.hasPrefix("file-write") {
                result.fileWriteRules.append(display)
            } else if op == "mach-lookup" || op == "mach-register" {
                result.machLookupRules.append(display)
            } else if op.hasPrefix("network") {
                result.networkRules.append(display)
            } else if op.hasPrefix("iokit") {
                result.iokitRules.append(display)
            }
            // Other operations (process-exec, signal, sysctl, etc.) are not
            // categorized in this version.
        }

        return result
    }

    /// Format a rule into a human-readable string.
    private func formatRule(_ rule: Rule) -> String {
        if rule.filter.isEmpty {
            return "(\(rule.action) \(rule.operation))"
        }
        return "(\(rule.action) \(rule.operation) \(rule.filter))"
    }
}
