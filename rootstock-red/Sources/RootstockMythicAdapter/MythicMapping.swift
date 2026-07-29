import Foundation
import RootstockCore

/// Mythic command-mapping schema for the optional, unlinked adapter target.
public struct MythicCommandMapping: Codable, Sendable, Equatable {
    public var mythicCommand: String
    public var orchardCollectorId: String?
    public var orchardCheckId: String?
    public var orchardActionId: String?

    public init(
        mythicCommand: String,
        orchardCollectorId: String? = nil,
        orchardCheckId: String? = nil,
        orchardActionId: String? = nil
    ) {
        self.mythicCommand = mythicCommand
        self.orchardCollectorId = orchardCollectorId
        self.orchardCheckId = orchardCheckId
        self.orchardActionId = orchardActionId
    }
}

public enum MythicAdapter {
    /// Static mappings only. No task handler or transport is implemented.
    public static let scaffoldMappings: [MythicCommandMapping] = [
        MythicCommandMapping(mythicCommand: "shell", orchardActionId: "lab.exec.shell"),
        MythicCommandMapping(mythicCommand: "ls", orchardCollectorId: "collect.host"),
    ]
}
