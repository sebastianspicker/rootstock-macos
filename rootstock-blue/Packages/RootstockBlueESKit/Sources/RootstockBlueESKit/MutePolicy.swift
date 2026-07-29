/// MutePolicy - Rootstock product source (see package README for product doctrine).
import Foundation

public struct MutePolicy: Sendable {
    public var pathPrefixes: [String]
    public var inverted: Bool

    public init(pathPrefixes: [String] = [], inverted: Bool = false) {
        self.pathPrefixes = pathPrefixes
        self.inverted = inverted
    }

    public func shouldMute(path: String) -> Bool {
        let matches = pathPrefixes.contains { path.hasPrefix($0) }
        return inverted ? !matches : matches
    }

    public static func merging(_ profile: ESSubscriptionProfile, extra: [String] = []) -> MutePolicy {
        MutePolicy(pathPrefixes: profile.defaultMutePrefixes + extra)
    }
}
