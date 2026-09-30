import Foundation
import Testing
@testable import MacEnumKit

@Suite struct LOOBinCatalogTests {
    @Test func embeddedCatalogLoadsFromTheEnumerationBundle() throws {
        let catalog = try LOOBinCatalog.loadEmbedded()
        // loobins_subset.json holds 10 entries; the built-in fallback used when the
        // bundled resource is missing holds only 3.
        #expect(catalog.entries.count == 10)
    }
}
