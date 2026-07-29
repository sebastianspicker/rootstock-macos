/// Privilege or capability required before a collector/action should run.
public enum PrivilegeRequirement: String, Codable, Sendable, CaseIterable {
    case user
    case root
    case fda
    case accessibility
    case screenRecording
    case inputMonitoring
    case network
    case labMode
}
