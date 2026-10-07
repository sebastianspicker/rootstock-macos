/// YAMLComments - comment stripping shared by the YAML-subset readers.
import Foundation

public enum YAMLComments {
    /// Removes a trailing `# comment`. A `#` only starts a comment at the start of the line or after
    /// whitespace, and never inside a quoted scalar (quotes open only after whitespace).
    public static func strip(_ line: String) -> String {
        var quote: Character?
        var previous: Character = " "
        for index in line.indices {
            let current = line[index]
            if let open = quote {
                if current == open { quote = nil }
            } else if isQuote(current) && isBlank(previous) {
                quote = current
            } else if current == "#" && isBlank(previous) {
                return String(line[..<index])
            }
            previous = current
        }
        return line
    }

    private static func isQuote(_ character: Character) -> Bool {
        character == "\"" || character == "'"
    }

    private static func isBlank(_ character: Character) -> Bool {
        character == " " || character == "\t"
    }
}
