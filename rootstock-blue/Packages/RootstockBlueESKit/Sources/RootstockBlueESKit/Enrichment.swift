import Foundation
import RootstockBlueCore

/// Codesign enrichment hooks (stub). Real implementation uses Security.framework.
public enum CodesignEnrichment {
    public struct Info: Sendable {
        public var signed: Bool
        public var signingID: String?
        public var teamID: String?
        public var cdhash: String?

        public init(signed: Bool, signingID: String? = nil, teamID: String? = nil, cdhash: String? = nil) {
            self.signed = signed
            self.signingID = signingID
            self.teamID = teamID
            self.cdhash = cdhash
        }
    }

    public static func enrich(path: String) -> Info {
        // Code-signing lookup is not implemented.
        Info(signed: false, signingID: nil, teamID: nil, cdhash: nil)
    }

    public static func apply(_ info: Info, to fields: inout [String: String]) {
        fields[FieldTaxonomy.processSigned] = info.signed ? "true" : "false"
        if let s = info.signingID { fields[FieldTaxonomy.processSigningID] = s }
        if let t = info.teamID { fields[FieldTaxonomy.processTeamID] = t }
        if let c = info.cdhash { fields[FieldTaxonomy.processCDHash] = c }
    }
}
