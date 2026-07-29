import Foundation
import RootstockCore

/// Multi-plane Wave-16 compound ranking (25 net-new themes / 50 red|blue half-pairs beyond Wave-15).
public struct Wave16MultiPlaneClusterCheck: Check {
    public static let id = "rootstock.check.vuln.wave16_multi_plane_cluster"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let planes = Self.pairPlanes(state: state)
        guard planes.count >= 2 else { return [] }
        return [Self.compoundFinding(planes: planes, state: state)]
    }
    private static func pairPlanes(state: CollectedState) -> [String] {
        communicationPlanes(state) + appDataPlanes(state) + servicePlanes(state) + cloudPlanes(state)
    }


    private static func communicationPlanes(_ state: CollectedState) -> [String] {
        presentPlaneNames([
            .init(name: "airplay_receiver_surface", isPresent: hasPlaneSurface(state.airplayReceiverSurface, isPresent: { $0.airplaySurfacePresent }, primaryCount: { $0.airplayDaemonPaths.count }, secondaryCount: { $0.airplayPrefPaths.count })),
            .init(name: "handoff_clipboard_depth", isPresent: hasPlaneSurface(state.handoffClipboardDepth, isPresent: { $0.handoffSurfacePresent }, primaryCount: { $0.handoffFrameworkPaths.count }, secondaryCount: { $0.clipboardPathHits.count })),
            .init(name: "imessage_path_plane", isPresent: hasPlaneSurface(state.imessagePathPlane, isPresent: { $0.imessageSurfacePresent }, primaryCount: { $0.messagesAppPaths.count }, secondaryCount: { $0.messagesDbPaths.count })),
            .init(name: "facetime_camera_surface", isPresent: hasPlaneSurface(state.facetimeCameraSurface, isPresent: { $0.facetimeSurfacePresent }, primaryCount: { $0.facetimeAppPaths.count }, secondaryCount: { $0.avConferencePaths.count })),
            .init(name: "finder_sync_extension", isPresent: hasPlaneSurface(state.finderSyncExtension, isPresent: { $0.finderSyncSurfacePresent }, primaryCount: { $0.finderSyncFrameworkPaths.count }, secondaryCount: { $0.appScriptPaths.count })),
            .init(name: "fileprovider_domain", isPresent: hasPlaneSurface(state.fileproviderDomain, isPresent: { $0.fileProviderSurfacePresent }, primaryCount: { $0.fileProviderFrameworkPaths.count }, secondaryCount: { $0.cloudStoragePaths.count })),
        ])
    }

    private static func appDataPlanes(_ state: CollectedState) -> [String] {
        presentPlaneNames([
            .init(name: "notification_center_depth", isPresent: hasPlaneSurface(state.notificationCenterDepth, isPresent: { $0.notificationSurfacePresent }, primaryCount: { $0.notificationFrameworkPaths.count }, secondaryCount: { $0.notificationStorePaths.count })),
            .init(name: "siri_suggestions_plane", isPresent: hasPlaneSurface(state.siriSuggestionsPlane, isPresent: { $0.siriSurfacePresent }, primaryCount: { $0.siriFrameworkPaths.count }, secondaryCount: { $0.suggestionsStorePaths.count })),
            .init(name: "spotlight_importer_depth", isPresent: hasPlaneSurface(state.spotlightImporterDepth, isPresent: { $0.spotlightImporterSurfacePresent }, primaryCount: { $0.metadataToolPaths.count }, secondaryCount: { $0.spotlightImporterPaths.count })),
            .init(name: "contacts_path_plane", isPresent: hasPlaneSurface(state.contactsPathPlane, isPresent: { $0.contactsSurfacePresent }, primaryCount: { $0.contactsAppPaths.count }, secondaryCount: { $0.addressBookPaths.count })),
            .init(name: "calendar_server_path", isPresent: hasPlaneSurface(state.calendarServerPath, isPresent: { $0.caldavSurfacePresent }, primaryCount: { $0.caldavFrameworkPaths.count }, secondaryCount: { $0.calendarsStorePaths.count })),
            .init(name: "reminders_cloud_path", isPresent: hasPlaneSurface(state.remindersCloudPath, isPresent: { $0.remindersCloudSurfacePresent }, primaryCount: { $0.remindersAppPaths.count }, secondaryCount: { $0.remindersStorePaths.count })),
        ])
    }

    private static func servicePlanes(_ state: CollectedState) -> [String] {
        presentPlaneNames([
            .init(name: "maps_location_path", isPresent: hasPlaneSurface(state.mapsLocationPath, isPresent: { $0.mapsLocationSurfacePresent }, primaryCount: { $0.mapsAppPaths.count }, secondaryCount: { $0.mapsCachePaths.count })),
            .init(name: "weather_widget_path", isPresent: hasPlaneSurface(state.weatherWidgetPath, isPresent: { $0.weatherSurfacePresent }, primaryCount: { $0.weatherAppPaths.count }, secondaryCount: { $0.weatherContainerPaths.count })),
            .init(name: "music_library_path", isPresent: hasPlaneSurface(state.musicLibraryPath, isPresent: { $0.musicSurfacePresent }, primaryCount: { $0.musicAppPaths.count }, secondaryCount: { $0.musicLibraryPaths.count })),
            .init(name: "books_path_plane", isPresent: hasPlaneSurface(state.booksPathPlane, isPresent: { $0.booksSurfacePresent }, primaryCount: { $0.booksAppPaths.count }, secondaryCount: { $0.booksContainerPaths.count })),
            .init(name: "podcasts_path_plane", isPresent: hasPlaneSurface(state.podcastsPathPlane, isPresent: { $0.podcastsSurfacePresent }, primaryCount: { $0.podcastsAppPaths.count }, secondaryCount: { $0.podcastsStorePaths.count })),
            .init(name: "tv_app_path_plane", isPresent: hasPlaneSurface(state.tvAppPathPlane, isPresent: { $0.tvSurfacePresent }, primaryCount: { $0.tvAppPaths.count }, secondaryCount: { $0.tvContainerPaths.count })),
        ])
    }

    private static func cloudPlanes(_ state: CollectedState) -> [String] {
        presentPlaneNames([
            .init(name: "homekit_path_plane", isPresent: hasPlaneSurface(state.homekitPathPlane, isPresent: { $0.homekitSurfacePresent }, primaryCount: { $0.homeAppPaths.count }, secondaryCount: { $0.homeKitStorePaths.count })),
            .init(name: "health_path_plane", isPresent: hasPlaneSurface(state.healthPathPlane, isPresent: { $0.healthSurfacePresent }, primaryCount: { $0.healthAppPaths.count }, secondaryCount: { $0.healthStorePaths.count })),
            .init(name: "wallet_pass_path", isPresent: hasPlaneSurface(state.walletPassPath, isPresent: { $0.walletSurfacePresent }, primaryCount: { $0.walletAppPaths.count }, secondaryCount: { $0.passesStorePaths.count })),
            .init(name: "findmy_path_plane", isPresent: hasPlaneSurface(state.findmyPathPlane, isPresent: { $0.findmySurfacePresent }, primaryCount: { $0.findMyAppPaths.count }, secondaryCount: { $0.findMyCachePaths.count })),
            .init(name: "shortcuts_icloud_sync", isPresent: hasPlaneSurface(state.shortcutsIcloudSync, isPresent: { $0.shortcutsIcloudSurfacePresent }, primaryCount: { $0.shortcutsAppPaths.count }, secondaryCount: { $0.shortcutsDbPaths.count })),
            .init(name: "devicemanagement_profile", isPresent: hasPlaneSurface(state.devicemanagementProfile, isPresent: { $0.deviceMgmtSurfacePresent }, primaryCount: { $0.profilesToolPaths.count }, secondaryCount: { $0.managedPrefPaths.count })),
            .init(name: "softwareupdate_catalog", isPresent: hasPlaneSurface(state.softwareupdateCatalog, isPresent: { $0.softwareUpdateSurfacePresent }, primaryCount: { $0.softwareUpdateToolPaths.count }, secondaryCount: { $0.softwareUpdatePrefPaths.count })),
        ])
    }
    private static func amplifiers(state: CollectedState) -> [String] {
        var amps: [String] = []
        if state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true { amps.append("remote") }
        if state.tcc?.fullDiskAccessLikely == true { amps.append("fda") }
        if state.protections?.sipEnabled == false { amps.append("sip_off") }
        if state.protections?.gatekeeperEnabled == false { amps.append("gk_off") }
        if let esf = state.esf, esf.clientPaths.isEmpty { amps.append("sensor_gap") }
        if state.securityProducts.filter(\.present).isEmpty { amps.append("products_absent") }
        return amps
    }
    private static func compoundFinding(planes: [String], state: CollectedState) -> Finding {
        let sorted = planes.sorted()
        let amps = amplifiers(state: state).sorted()
        let severity: Severity = (sorted.count >= 6 && amps.contains("remote") && amps.contains("fda")) ? .high
            : ((sorted.count >= 3 || (sorted.count >= 2 && amps.count >= 2)) ? .medium : .low)
        return Finding(id: "\(id).multi_plane", title: "Wave-16 multi-plane compound: \(sorted.count) planes (\(sorted.joined(separator: ", ")))", severity: severity, category: .misconfig, resolution: .init(evidence: [
                Evidence(type: "planes", detail: "planes=\(sorted.joined(separator: "|")) count=\(sorted.count)"),
                Evidence(type: "amplifiers", detail: amps.isEmpty ? "amplifiers=none" : "amplifiers=\(amps.joined(separator: "|")) count=\(amps.count)"),
                Evidence(type: "stage_labels", detail: "stages=collection|privacy|mdm|media|automation (labels only - not auto-exploit)"),
                Evidence(type: "host", detail: "host=\(state.host?.hostname ?? "unknown") user=\(state.host?.username ?? "unknown")"),
                Evidence(type: "honesty", detail: "Wave-16 multi-plane ranking is path-to-impact narrative across 25 planes / 50 red|blue half-pairs. Rootstock Red does not dump app contents, location, Health/Wallet secrets, install MDM profiles, or rewrite Software Update catalogs."),
            ], attackTechniques: ["T1005", "T1083", "T1213", "T1484", "T1072", "T1115"], remediation: [
                "Prioritize hosts co-locating multiple Wave-16 planes with remote/FDA amplifiers",
                "Close remote access before deep dual-use inventory",
                "Use Wave-16 lab plans under ROE for purple validation",
                "OPSEC: multi-plane compounds are engagement narrative, not exploit scripts",
            ], falsePositiveNotes: "Consumer Macs co-locate many first-party app path planes. Rank production remote hosts with FDA amplifiers first."), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 28, esfExpected: ["OPEN", "EXEC", "READ"]))
    }
}
