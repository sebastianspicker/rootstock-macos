import Foundation
import RootstockCore
import MacTransportKit

/// Task model for the optional runtime, which is not linked into the default executable.
public struct AgentTask: Codable, Sendable, Equatable, Identifiable {
    public var id: String
    public var command: String
    public var arguments: [String]
    public var createdAt: Date

    public init(
        id: String = UUID().uuidString,
        command: String,
        arguments: [String] = [],
        createdAt: Date = Date()
    ) {
        self.id = id
        self.command = command
        self.arguments = arguments
        self.createdAt = createdAt
    }
}

/// Scheduling and expiry configuration for the optional runtime.
public struct AgentSessionConfig: Codable, Sendable, Equatable {
    public var sleepSeconds: Int
    public var jitterPercent: Int
    public var killDate: Date?
    public var beaconMode: Bool

    public init(
        sleepSeconds: Int = 60,
        jitterPercent: Int = 20,
        killDate: Date? = nil,
        beaconMode: Bool = true
    ) {
        self.sleepSeconds = sleepSeconds
        self.jitterPercent = jitterPercent
        self.killDate = killDate
        self.beaconMode = beaconMode
    }
}

/// Nonfunctional runtime boundary retained for compile-time API compatibility.
public struct AgentRuntime: Sendable {
    public var config: AgentSessionConfig
    public var transport: HTTPTransport?

    public init(config: AgentSessionConfig = AgentSessionConfig(), transport: HTTPTransport? = nil) {
        self.config = config
        self.transport = transport
    }

    public func start() async throws {
        throw RootstockError.invalidArgument(
            "MacAgentKit execution is disabled; see NOT_FOR_PRODUCTION_IMPLANT.md"
        )
    }
}
