import Foundation

/// Severity of a security finding.
public enum Severity: String, Codable, Sendable, CaseIterable {
    case info
    case low
    case medium
    case high
    case critical
}

/// Confidence that the finding is correct / exploitable.
public enum Confidence: String, Codable, Sendable, CaseIterable {
    case low
    case medium
    case high
}

/// High-level finding category (maps to vuln planes + enum themes).
public enum FindingCategory: String, Codable, Sendable, CaseIterable {
    case host
    case tcc
    case mdm
    case persist
    case lool
    case sandbox
    case xpc
    case cve
    case auth
    case network
    case codesign
    case securityProduct
    case misconfig
    case other
}

/// Single piece of evidence backing a finding.
public struct Evidence: Codable, Sendable, Equatable {
    public var type: String
    public var path: String?
    public var detail: String
    public var hash: String?

    public init(type: String, path: String? = nil, detail: String, hash: String? = nil) {
        self.type = type
        self.path = path
        self.detail = detail
        self.hash = hash
    }
}

/// Evidence-grade assessment finding (schema v1).
public struct Finding: Codable, Sendable, Identifiable, Equatable {
    public struct Resolution: Sendable {
        public var evidence: [Evidence] = []
        public var attackTechniques: [String] = []
        public var remediation: [String] = []
        public var falsePositiveNotes: String? = nil

        public init(evidence: [Evidence] = [], attackTechniques: [String] = [], remediation: [String] = [], falsePositiveNotes: String? = nil) {
            self.evidence = evidence
            self.attackTechniques = attackTechniques
            self.remediation = remediation
            self.falsePositiveNotes = falsePositiveNotes
        }
    }

    public struct Runtime: Sendable {
        public var confidence: Confidence = .medium
        public var dryRunSafe: Bool = true
        public var opsecScore: Int? = nil
        public var tccDomains: [String] = []
        public var esfExpected: [String] = []
        public var osRange: String? = nil

        public init(confidence: Confidence = .medium, dryRunSafe: Bool = true, opsecScore: Int? = nil, tccDomains: [String] = [], esfExpected: [String] = [], osRange: String? = nil) {
            self.confidence = confidence
            self.dryRunSafe = dryRunSafe
            self.opsecScore = opsecScore
            self.tccDomains = tccDomains
            self.esfExpected = esfExpected
            self.osRange = osRange
        }
    }

    public var id: String
    public var title: String
    public var severity: Severity
    public var confidence: Confidence
    public var category: FindingCategory
    public var evidence: [Evidence]
    public var attackTechniques: [String]
    public var remediation: [String]
    public var falsePositiveNotes: String?
    public var dryRunSafe: Bool
    /// 0–100; higher means noisier (more OPSEC risk).
    public var opsecScore: Int?
    public var tccDomains: [String]
    public var esfExpected: [String]
    public var osRange: String?

    public init(
        id: String,
        title: String,
        severity: Severity,
        category: FindingCategory,
        resolution: Resolution = .init(),
        runtime: Runtime = .init()
    ) {
        self.id = id
        self.title = title
        self.severity = severity
        self.confidence = runtime.confidence
        self.category = category
        self.evidence = resolution.evidence
        self.attackTechniques = resolution.attackTechniques
        self.remediation = resolution.remediation
        self.falsePositiveNotes = resolution.falsePositiveNotes
        self.dryRunSafe = runtime.dryRunSafe
        self.opsecScore = runtime.opsecScore
        self.tccDomains = runtime.tccDomains
        self.esfExpected = runtime.esfExpected
        self.osRange = runtime.osRange
    }
}
