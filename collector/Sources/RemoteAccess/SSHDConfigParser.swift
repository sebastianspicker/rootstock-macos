import Darwin
import Foundation
import HostCommand

/// Reads the security directives sshd actually applies by default.
///
/// sshd keeps the first value it sees for a directive, so later lines never override earlier
/// ones. `Include` pulls other files in at the point it appears (relative patterns resolve
/// against `/etc/ssh`; macOS ships `Include /etc/ssh/sshd_config.d/*`). Lines after a `Match`
/// only apply to some connections: recording stops there for the rest of that file and
/// `match_blocks = yes` tells consumers that values may be overridden for some clients.
struct SSHDConfigParser {
    static let canonicalKeys: [String: String] = [
        "port": "Port",
        "permitrootlogin": "PermitRootLogin",
        "passwordauthentication": "PasswordAuthentication",
        "pubkeyauthentication": "PubkeyAuthentication",
    ]
    static let maximumIncludedFiles = 32
    static let includeBaseDirectory = "/etc/ssh"

    /// Paths matching an `Include` pattern, in the order sshd reads them.
    let expandInclude: (String) -> [String]
    /// Contents of an included file; nil when it cannot be read.
    let readInclude: (String) -> String?

    private(set) var directives: [String: String] = [:]
    private var includedFiles = 0

    init(
        expandInclude: @escaping (String) -> [String] = Self.globPaths,
        readInclude: @escaping (String) -> String? = Self.readBounded
    ) {
        self.expandInclude = expandInclude
        self.readInclude = readInclude
    }

    /// Directives of `contents` plus its includes, with `match_blocks` when any `Match` exists.
    mutating func parse(_ contents: String) -> [String: String] {
        process(contents)
        return directives
    }

    private mutating func process(_ contents: String) {
        for line in contents.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { continue }
            let (key, value) = Self.splitDirective(trimmed)
            if key == "match" {
                directives["match_blocks"] = "yes"
                return
            }
            guard !value.isEmpty else { continue }
            if key == "include" {
                processInclude(value)
            } else if let canonical = Self.canonicalKeys[key], directives[canonical] == nil {
                directives[canonical] = value
            }
        }
    }

    /// Lowercased keyword and argument; sshd_config(5) separates them with whitespace and/or one `=`,
    /// and allows the argument in double quotes.
    private static func splitDirective(_ line: String) -> (key: String, value: String) {
        let keyEnd = line.firstIndex { $0.isWhitespace || $0 == "=" } ?? line.endIndex
        var value = line[keyEnd...].trimmingCharacters(in: .whitespaces)
        if value.hasPrefix("=") {
            value = String(value.dropFirst()).trimmingCharacters(in: .whitespaces)
        }
        if value.count >= 2, value.hasPrefix("\""), value.hasSuffix("\"") {
            value = String(value.dropFirst().dropLast())
        }
        return (line[..<keyEnd].lowercased(), value)
    }

    private mutating func processInclude(_ value: String) {
        for pattern in value.split(whereSeparator: \.isWhitespace).map(String.init) {
            let absolute = pattern.hasPrefix("/") ? pattern : "\(Self.includeBaseDirectory)/\(pattern)"
            for path in expandInclude(absolute) {
                guard includedFiles < Self.maximumIncludedFiles else { return }
                includedFiles += 1
                if let contents = readInclude(path) {
                    process(contents)
                }
            }
        }
    }

    /// `glob(3)` expansion; glob sorts matches, which is the order sshd uses.
    static func globPaths(_ pattern: String) -> [String] {
        var matches = glob_t()
        defer { globfree(&matches) }
        guard glob(pattern, 0, nil, &matches) == 0 else { return [] }
        return (0..<Int(matches.gl_pathc)).compactMap { index in
            matches.gl_pathv[index].map { String(cString: $0) }
        }
    }

    static func readBounded(_ path: String) -> String? {
        (try? BoundedFileReader.read(path: path)).map { String(decoding: $0, as: UTF8.self) }
    }
}
