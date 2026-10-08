import Foundation

/// Redacts secret-looking values from launchd `ProgramArguments` before they are recorded.
///
/// `argv[0]` is kept. In every later argument the following are replaced with `<redacted>`:
/// the argument after a flag named like a secret (`--password`, `-token`, `--api-key`, ...),
/// the value of `key=value` when the key is named like a secret, the userinfo, query and
/// fragment of URLs with a scheme, and runs of 20 or more hex or mixed-case base64 characters.
/// The rest of each argument is kept.
enum ArgumentRedaction {
    static let placeholder = "<redacted>"

    private static let secretName = try! NSRegularExpression(
        pattern: "(pass(w(or)?d)?|secret|token|api[-_]?key|auth|bearer|credential|private|key)$",
        options: [.caseInsensitive]
    )
    private static let urlPattern = try! NSRegularExpression(
        pattern: "[A-Za-z][A-Za-z0-9+.-]*://[^\\s\"'<>]+"
    )
    private static let tokenPattern = try! NSRegularExpression(pattern: "[A-Za-z0-9+_-]{20,}={0,2}")

    static func redact(_ arguments: [String]) -> [String] {
        arguments.enumerated().map { index, argument in
            guard index > 0 else { return argument }
            if index > 1, isSecretFlag(arguments[index - 1]) { return placeholder }
            return redactTokens(redactKeyValue(redactURLs(argument)))
        }
    }

    /// True for `-x`/`--x` flags without an inline value whose name looks like a secret.
    static func isSecretFlag(_ argument: String) -> Bool {
        guard argument.hasPrefix("-"), !argument.contains("=") else { return false }
        return isSecretName(String(argument.drop { $0 == "-" }))
    }

    static func isSecretName(_ name: String) -> Bool {
        !name.isEmpty && secretName.firstMatch(in: name, range: NSRange(name.startIndex..., in: name)) != nil
    }

    /// `key=<redacted>` when the key (leading dashes ignored) looks like a secret.
    static func redactKeyValue(_ argument: String) -> String {
        guard let equals = argument.firstIndex(of: "=") else { return argument }
        let key = argument[..<equals]
        guard isSecretName(String(key.drop { $0 == "-" })) else { return argument }
        return "\(key)=\(placeholder)"
    }

    /// Userinfo, query and fragment of every `scheme://` URL inside `argument`.
    static func redactURLs(_ argument: String) -> String {
        replacingMatches(of: urlPattern, in: argument) { redactURL($0) }
    }

    static func redactURL(_ url: String) -> String {
        guard let separator = url.range(of: "://") else { return url }
        let scheme = url[..<separator.upperBound]
        var rest = Substring(url[separator.upperBound...])
        var fragment = ""
        if let hash = rest.firstIndex(of: "#") {
            fragment = "#\(placeholder)"
            rest = rest[..<hash]
        }
        var query = ""
        if let question = rest.firstIndex(of: "?") {
            query = "?\(placeholder)"
            rest = rest[..<question]
        }
        let authorityEnd = rest.firstIndex(of: "/") ?? rest.endIndex
        if let at = rest[..<authorityEnd].lastIndex(of: "@") {
            rest = Substring("\(placeholder)@\(rest[rest.index(after: at)...])")
        }
        return "\(scheme)\(rest)\(query)\(fragment)"
    }

    /// Runs of 20+ characters that are all hex, or mix upper case, lower case and digits.
    static func redactTokens(_ argument: String) -> String {
        replacingMatches(of: tokenPattern, in: argument) { run in
            isTokenLike(run) ? placeholder : run
        }
    }

    static func isTokenLike(_ run: String) -> Bool {
        let body = String(run.drop { $0 == "-" }).trimmingCharacters(in: CharacterSet(charactersIn: "="))
        guard body.count >= 20 else { return false }
        if body.allSatisfy(\.isHexDigit) { return true }
        return body.contains(where: \.isUppercase) && body.contains(where: \.isLowercase)
            && body.contains(where: \.isNumber)
    }

    private static func replacingMatches(
        of expression: NSRegularExpression,
        in text: String,
        transform: (String) -> String
    ) -> String {
        var result = ""
        var cursor = text.startIndex
        for match in expression.matches(in: text, range: NSRange(text.startIndex..., in: text)) {
            guard let range = Range(match.range, in: text) else { continue }
            result += text[cursor..<range.lowerBound]
            result += transform(String(text[range]))
            cursor = range.upperBound
        }
        return result + text[cursor...]
    }
}
