import Foundation

/// Weights for OPSEC score v0 (higher contribution = noisier).
public struct OpsecWeights: Sendable {
    public var processSpawn: Int
    public var sensitiveFileOpen: Int
    public var tccDomainTouch: Int
    public var networkEgress: Int
    public var userVisible: Int
    public var esfEventClass: Int
    public var sensitivePathRead: Int
    public var appleEvents: Int

    public init(
        processSpawn: Int = 15,
        sensitiveFileOpen: Int = 10,
        tccDomainTouch: Int = 20,
        networkEgress: Int = 25,
        userVisible: Int = 30,
        esfEventClass: Int = 5,
        sensitivePathRead: Int = 8,
        appleEvents: Int = 20
    ) {
        self.processSpawn = processSpawn
        self.sensitiveFileOpen = sensitiveFileOpen
        self.tccDomainTouch = tccDomainTouch
        self.networkEgress = networkEgress
        self.userVisible = userVisible
        self.esfEventClass = esfEventClass
        self.sensitivePathRead = sensitivePathRead
        self.appleEvents = appleEvents
    }

    public static let `default` = OpsecWeights()
}

/// Inputs for computing an OPSEC score.
public struct OpsecSignals: Sendable {
    public var processSpawns: Int
    public var sensitiveFileOpens: Int
    public var tccDomains: [String]
    public var networkEgress: Bool
    public var userVisible: Bool
    /// Endpoint Security-style class names (e.g. `NOTIFY_OPEN`).
    public var esfEventClasses: [String]
    /// Count of evidence paths that look privacy/credential sensitive.
    public var sensitivePathReads: Int
    /// Whether Apple Events / Automation TCC domain is in play.
    public var appleEvents: Bool

    public init(
        processSpawns: Int = 0,
        sensitiveFileOpens: Int = 0,
        tccDomains: [String] = [],
        networkEgress: Bool = false,
        userVisible: Bool = false,
        esfEventClasses: [String] = [],
        sensitivePathReads: Int = 0,
        appleEvents: Bool = false
    ) {
        self.processSpawns = processSpawns
        self.sensitiveFileOpens = sensitiveFileOpens
        self.tccDomains = tccDomains
        self.networkEgress = networkEgress
        self.userVisible = userVisible
        self.esfEventClasses = esfEventClasses
        self.sensitivePathReads = sensitivePathReads
        self.appleEvents = appleEvents
    }
}
