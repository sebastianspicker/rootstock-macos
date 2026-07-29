import XCTest
import RootstockCore
import MacIdentityKit
import MacMdmKit
import MacLolKit
@testable import MacEnumKit

/// Real collectors for alpha polish themes (identity, MDM, LOL planner).
final class AlphaPolishCollectorTests: XCTestCase {
    func testIdentityPostureNotScaffold() async throws {
        let state = try await IdentityPostureCollector().collect(context: .assess())
        XCTAssertNotNil(state.identity)
        let notes = state.identity?.notes.joined(separator: " ") ?? ""
        XCTAssertFalse(notes.localizedCaseInsensitiveContains("scaffold stub"))
        XCTAssertFalse(notes.isEmpty)
        XCTAssertEqual(state.collectorNotes[IdentityPostureCollector.id]?.isEmpty, false)
        // Probe must set structured fields (bools may be nil when unknown).
        XCTAssertNotNil(state.identity?.notes)
    }

    func testMDMPostureBeyondVendorOnly() async throws {
        let state = try await MdmPostureCollector().collect(context: .assess())
        XCTAssertNotNil(state.mdm)
        let notes = state.mdm?.notes.joined(separator: " ") ?? ""
        XCTAssertFalse(notes.localizedCaseInsensitiveContains("scaffold"))
        // Alpha: managed prefs or profile fields exist as structured state
        let mdm = try XCTUnwrap(state.mdm)
        // managedPreferenceNames may be empty if unreadable; notes must document attempt
        XCTAssertFalse(mdm.notes.isEmpty)
        XCTAssertNotNil(state.collectorNotes[MdmPostureCollector.id])
    }

    func testLOLPlannerRanksPresentBins() throws {
        let catalog = try LOOBinCatalog.loadEmbedded()
        let planner = LOLPlanner(catalog: catalog)
        let ranked = planner.plan(goal: .discovery)
        // On a real Mac, system_profiler / mdfind etc. usually present
        XCTAssertFalse(ranked.isEmpty, "expected ranked discovery LOOBins on host")
        // Noise ascending
        for i in 1..<ranked.count {
            XCTAssertLessThanOrEqual(ranked[i - 1].noiseScore, ranked[i].noiseScore)
        }
    }

    func testLOOBinsCollectorFillsPlans() async throws {
        let state = try await LOOBinsCollector().collect(context: .assess(profile: .standard))
        XCTAssertFalse(state.loobins.isEmpty)
        // Planner output for standard alpha
        XCTAssertFalse(
            state.lolPlans.isEmpty,
            "lolPlans should be filled by LOOBinsCollector for alpha planner"
        )
    }
}
