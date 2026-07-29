/// CaseManifest - Rootstock product source (see package README for product doctrine).
import Foundation
import RootstockBlueCore

public struct CaseManifest: Codable, Sendable {
    public var caseID: UUID
    public var name: String
    public var createdAt: Date
    public var productVersion: String
    public var formatVersion: Int
    public var mode: ProductMode?
    public var notes: String

    public init(
        caseID: UUID = UUID(),
        name: String,
        createdAt: Date = Date(),
        productVersion: String = RootstockBlueVersion.string,
        formatVersion: Int = RootstockBlueVersion.casePackageFormat,
        mode: ProductMode? = nil,
        notes: String = ""
    ) {
        self.caseID = caseID
        self.name = name
        self.createdAt = createdAt
        self.productVersion = productVersion
        self.formatVersion = formatVersion
        self.mode = mode
        self.notes = notes
    }
}
