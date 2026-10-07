import Foundation

/// Parses sandbox profile text (SBPL - Sandbox Profile Language) into
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
        let scalars = Array(text.unicodeScalars)

        // Linear scan for `(allow|deny <operation> [filter])`. The filter body
        // may contain parenthesised groups nested up to two levels deep; deeper
        // nesting is not matched. A full recursive-descent parser would be
        // needed for complete accuracy, but this is sufficient for extracting
        // the operation type and top-level filter for categorization purposes.
        // Each start position is scanned once with no backtracking, so run time
        // is bounded by the input length per directive start.
        var index = 0
        while index < scalars.count {
            guard scalars[index] == "(", let parsed = parseRule(scalars, openIndex: index) else {
                index += 1
                continue
            }
            rules.append(parsed.rule)
            index = parsed.endIndex
        }

        return rules
    }

    private func parseRule(_ scalars: [Unicode.Scalar], openIndex: Int) -> (rule: Rule, endIndex: Int)? {
        func isSpace(_ scalar: Unicode.Scalar) -> Bool { scalar.properties.isWhitespace }
        func isOperationScalar(_ scalar: Unicode.Scalar) -> Bool {
            scalar == "_" || scalar == "-" || scalar == "*"
                || scalar.properties.isAlphabetic
                || scalar.properties.numericType != nil
        }
        func skipSpaces(_ position: Int) -> Int {
            var position = position
            while position < scalars.count, isSpace(scalars[position]) { position += 1 }
            return position
        }

        guard let (action, actionEnd) = ruleAction(in: scalars, at: openIndex + 1) else { return nil }
        var position = actionEnd

        let afterAction = skipSpaces(position)
        guard afterAction > position else { return nil }
        position = afterAction

        let operationStart = position
        while position < scalars.count, isOperationScalar(scalars[position]) { position += 1 }
        guard position > operationStart else { return nil }
        let operation = String(String.UnicodeScalarView(scalars[operationStart..<position]))

        var filter = ""
        let afterOperation = skipSpaces(position)
        if afterOperation > position {
            position = afterOperation
            let filterStart = position
            guard let filterEnd = filterEndIndex(in: scalars, from: filterStart) else { return nil }
            position = filterEnd
            filter = String(String.UnicodeScalarView(scalars[filterStart..<position]))
        }

        guard position < scalars.count, scalars[position] == ")" else { return nil }
        return (Rule(action: action, operation: operation, filter: filter), position + 1)
    }

    private func ruleAction(in scalars: [Unicode.Scalar], at start: Int) -> (String, Int)? {
        for candidate in ["allow", "deny"] {
            let end = start + candidate.unicodeScalars.count
            if end <= scalars.count, String(String.UnicodeScalarView(scalars[start..<end])) == candidate {
                return (candidate, end)
            }
        }
        return nil
    }

    /// Locate the closing directive parenthesis without consuming it.
    private func filterEndIndex(in scalars: [Unicode.Scalar], from start: Int) -> Int? {
        var position = start
        var depth = 0
        while position < scalars.count {
            let scalar = scalars[position]
            if scalar == "(" {
                depth += 1
                if depth > 2 { return nil }
            } else if scalar == ")" {
                if depth == 0 { return position }
                depth -= 1
            }
            position += 1
        }
        return nil
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
