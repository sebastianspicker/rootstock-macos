import Foundation

/// Typed errors for Rootstock Red platform operations.
public enum RootstockError: Error, Sendable, Equatable {
    case killSwitchActive(path: String)
    case unauthorized(reason: String)
    case labNotCompiled
    case tccDenied(domain: String)
    case collectorFailed(id: String, message: String)
    case checkFailed(id: String, message: String)
    case invalidArgument(String)
    case io(String)
}

extension RootstockError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .killSwitchActive(let path):
            return "Rootstock Red disabled by kill switch at \(path)"
        case .unauthorized(let reason):
            return "Unauthorized: \(reason)"
        case .labNotCompiled:
            return "Lab actions are not compiled into this assess build"
        case .tccDenied(let domain):
            return "TCC denied or unavailable for domain: \(domain)"
        case .collectorFailed(let id, let message):
            return "Collector \(id) failed: \(message)"
        case .checkFailed(let id, let message):
            return "Check \(id) failed: \(message)"
        case .invalidArgument(let message):
            return message
        case .io(let message):
            return message
        }
    }
}
