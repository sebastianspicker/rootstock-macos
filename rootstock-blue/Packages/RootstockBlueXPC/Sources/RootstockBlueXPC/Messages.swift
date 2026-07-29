/// Messages - Rootstock product source (see package README for product doctrine).
import Foundation
import RootstockBlueCore

public struct XPCRequest: Codable, Sendable {
    public var id: UUID
    public var capability: XPCCapability
    public var profile: String?
    public var packName: String?
    public var exportPath: String?

    public init(
        id: UUID = UUID(),
        capability: XPCCapability,
        profile: String? = nil,
        packName: String? = nil,
        exportPath: String? = nil
    ) {
        self.id = id
        self.capability = capability
        self.profile = profile
        self.packName = packName
        self.exportPath = exportPath
    }
}

public struct XPCResponse: Codable, Sendable {
    public var id: UUID
    public var ok: Bool
    public var message: String
    public var lossCounters: LossCounters?

    public init(id: UUID, ok: Bool, message: String, lossCounters: LossCounters? = nil) {
        self.id = id
        self.ok = ok
        self.message = message
        self.lossCounters = lossCounters
    }
}
