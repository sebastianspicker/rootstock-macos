/// PluginManifest - Rootstock product source (see package README for product doctrine).
import Foundation

public enum ParserTier: Int, Codable, Sendable {
    case tier1 = 1
    case tier2 = 2
    case tier3 = 3
}

public struct PluginManifest: Codable, Sendable {
    public var id: String
    public var tier: ParserTier
    public var supportedOS: [String]
    public var description: String

    public init(id: String, tier: ParserTier, supportedOS: [String] = ["14+", "15+"], description: String) {
        self.id = id
        self.tier = tier
        self.supportedOS = supportedOS
        self.description = description
    }
}
