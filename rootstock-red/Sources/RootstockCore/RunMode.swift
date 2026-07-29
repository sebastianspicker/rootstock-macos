/// Execution mode for Rootstock Red runs.
public enum RunMode: String, Codable, Sendable, CaseIterable {
    /// Default: read-only collectors and checks.
    case assess
    /// Gated mutating / simulation actions (not in default binary).
    case lab
    /// Detection-engineering twin of techniques.
    case purple
    /// Optional agent runtime (not in default binary).
    case agent
}
