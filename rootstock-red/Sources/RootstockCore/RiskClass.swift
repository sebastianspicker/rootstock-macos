/// Risk class of a module (default product surface is readOnly only).
public enum RiskClass: String, Codable, Sendable, CaseIterable {
    case readOnly
    case mutate
    case destructive
    case labOnly
}
