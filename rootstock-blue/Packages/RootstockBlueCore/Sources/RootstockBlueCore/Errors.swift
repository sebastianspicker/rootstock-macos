/// Errors - Rootstock product source (see package README for product doctrine).
import Foundation

public enum RootstockBlueError: Error, LocalizedError, Sendable {
    case caseNotFound(URL)
    case caseAlreadyExists(URL)
    case invalidCasePackage(String)
    case schemaMigrationFailed(String)
    case io(String)
    case preflightFailed([String])
    case detectionRuleInvalid(String)
    case fixtureMissing(String)
    case notImplemented(String)
    case xpcDenied(String)
    case secretsRequired(String)

    public var errorDescription: String? {
        switch self {
        case .caseNotFound(let url):
            return "Case package not found: \(url.path)"
        case .caseAlreadyExists(let url):
            return "Case package already exists: \(url.path)"
        case .invalidCasePackage(let reason):
            return "Invalid case package: \(reason)"
        case .schemaMigrationFailed(let reason):
            return "Schema migration failed: \(reason)"
        case .io(let reason):
            return "I/O error: \(reason)"
        case .preflightFailed(let items):
            return "Preflight failed: \(items.joined(separator: "; "))"
        case .detectionRuleInvalid(let reason):
            return "Invalid detection rule: \(reason)"
        case .fixtureMissing(let path):
            return "Detection fixture missing: \(path)"
        case .notImplemented(let feature):
            return "Not implemented: \(feature)"
        case .xpcDenied(let op):
            return "XPC operation not allowlisted: \(op)"
        case .secretsRequired(let detail):
            return "User/org secrets required (no crack path): \(detail)"
        }
    }
}
