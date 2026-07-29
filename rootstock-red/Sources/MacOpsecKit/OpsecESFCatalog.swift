import Foundation
import RootstockCore

/// Maps finding categories / short ESF class names to Endpoint Security notify strings.
///
/// Short names (`OPEN`, `WRITE`, …) are stored on `Finding.esfExpected` for schema stability.
/// `NOTIFY_*` forms are used in OPSEC signal breakdowns and purple-team expectation maps.
public enum OpsecESFCatalog: Sendable {
    /// Canonical short classes when a finding leaves `esfExpected` empty.
    public static func defaultShortClasses(for category: FindingCategory) -> [String] {
        switch category {
        case .persist:
            return ["OPEN", "WRITE"]
        case .tcc, .auth, .codesign, .securityProduct, .mdm, .sandbox, .xpc, .misconfig:
            return ["OPEN"]
        case .lool:
            return ["OPEN", "EXEC"]
        case .network:
            return ["OPEN", "CONNECT"]
        case .host, .cve:
            return []
        case .other:
            return ["OPEN"]
        }
    }

    /// Convert short or mixed class names to `NOTIFY_*` Endpoint Security event type labels.
    public static func notifyEventNames(from classes: [String]) -> [String] {
        classes.map(notifyEventName)
    }

    private static let notifyNames = ["OPEN": "NOTIFY_OPEN", "WRITE": "NOTIFY_WRITE", "EXEC": "NOTIFY_EXEC", "FORK": "NOTIFY_FORK", "CREATE": "NOTIFY_CREATE", "RENAME": "NOTIFY_RENAME", "UNLINK": "NOTIFY_UNLINK", "MMAP": "NOTIFY_MMAP", "CONNECT": "NOTIFY_UIPC_CONNECT", "UIPC_CONNECT": "NOTIFY_UIPC_CONNECT", "LOOKUP": "NOTIFY_LOOKUP", "SIGNAL": "NOTIFY_SIGNAL", "GET_TASK": "NOTIFY_GET_TASK", "USER_PROMPT": "USER_PROMPT"]
    private static func notifyEventName(_ raw: String) -> String {
        let upper = raw.uppercased()
        if upper.hasPrefix("ES_EVENT_TYPE_NOTIFY_") { return String(upper.dropFirst("ES_EVENT_TYPE_".count)) }
        if upper.hasPrefix("NOTIFY_") { return upper }
        return notifyNames[upper] ?? "NOTIFY_" + upper
    }

    /// Default NOTIFY_* set for a category (via short-class defaults).
    public static func defaultNotifyEventNames(for category: FindingCategory) -> [String] {
        notifyEventNames(from: defaultShortClasses(for: category))
    }

    /// Heuristic: path looks sensitive for OPSEC path-read accounting.
    public static func isSensitivePath(_ path: String) -> Bool {
        let p = path.lowercased()
        let needles = [
            "/library/application support/com.apple.tcc",
            "/library/safari/",
            "/library/mail/",
            "/library/messages/",
            "/library/cookies/",
            "/library/keychains/",
            "/library/calendars/",
            "/library/reminders/",
            "/library/containers/",
            "/library/group containers/",
            "/library/accounts/",
            "/.ssh/",
            "/.aws/",
            "/.gnupg/",
            "tcc.db",
            "chat.db",
            "history.db",
            "cookies.binarycookies",
            "login.keychain",
            "kcpassword",
        ]
        return needles.contains { p.contains($0) }
    }
}
