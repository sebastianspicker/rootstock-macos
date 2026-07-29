import Foundation
/// Maps / location services residual plane (never dumps location history or spoofs CoreLocation positions).
public struct MapsLocationPathState: Codable, Sendable, Equatable {
    public var mapsAppPaths: [String]
    public var mapsCachePaths: [String]
    public var locationdPaths: [String]
    public var mapsLocationSurfacePresent: Bool?
    public var notes: [String]
    public init(
        mapsAppPaths: [String] = [],
        mapsCachePaths: [String] = [],
        locationdPaths: [String] = [],
        mapsLocationSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.mapsAppPaths = mapsAppPaths
        self.mapsCachePaths = mapsCachePaths
        self.locationdPaths = locationdPaths
        self.mapsLocationSurfacePresent = mapsLocationSurfacePresent
        self.notes = notes
    }
}


/// Weather / widget data residual plane (never dumps weather personalization data or widget timeline contents).
public struct WeatherWidgetPathState: Codable, Sendable, Equatable {
    public var weatherAppPaths: [String]
    public var weatherContainerPaths: [String]
    public var widgetServicePaths: [String]
    public var weatherSurfacePresent: Bool?
    public var notes: [String]
    public init(
        weatherAppPaths: [String] = [],
        weatherContainerPaths: [String] = [],
        widgetServicePaths: [String] = [],
        weatherSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.weatherAppPaths = weatherAppPaths
        self.weatherContainerPaths = weatherContainerPaths
        self.widgetServicePaths = widgetServicePaths
        self.weatherSurfacePresent = weatherSurfacePresent
        self.notes = notes
    }
}


/// Music / media library path residual (never exports Music library media or DRM material).
public struct MusicLibraryPathState: Codable, Sendable, Equatable {
    public var musicAppPaths: [String]
    public var musicLibraryPaths: [String]
    public var musicPrefPaths: [String]
    public var musicSurfacePresent: Bool?
    public var notes: [String]
    public init(
        musicAppPaths: [String] = [],
        musicLibraryPaths: [String] = [],
        musicPrefPaths: [String] = [],
        musicSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.musicAppPaths = musicAppPaths
        self.musicLibraryPaths = musicLibraryPaths
        self.musicPrefPaths = musicPrefPaths
        self.musicSurfacePresent = musicSurfacePresent
        self.notes = notes
    }
}


/// Books / EPUB path residual plane (never extracts EPUB contents or Books annotations as bulk export).
public struct BooksPathPlaneState: Codable, Sendable, Equatable {
    public var booksAppPaths: [String]
    public var booksContainerPaths: [String]
    public var booksPrefPaths: [String]
    public var booksSurfacePresent: Bool?
    public var notes: [String]
    public init(
        booksAppPaths: [String] = [],
        booksContainerPaths: [String] = [],
        booksPrefPaths: [String] = [],
        booksSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.booksAppPaths = booksAppPaths
        self.booksContainerPaths = booksContainerPaths
        self.booksPrefPaths = booksPrefPaths
        self.booksSurfacePresent = booksSurfacePresent
        self.notes = notes
    }
}


/// Podcasts library path residual (never dumps podcast episode files or account tokens).
public struct PodcastsPathPlaneState: Codable, Sendable, Equatable {
    public var podcastsAppPaths: [String]
    public var podcastsStorePaths: [String]
    public var podcastsPrefPaths: [String]
    public var podcastsSurfacePresent: Bool?
    public var notes: [String]
    public init(
        podcastsAppPaths: [String] = [],
        podcastsStorePaths: [String] = [],
        podcastsPrefPaths: [String] = [],
        podcastsSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.podcastsAppPaths = podcastsAppPaths
        self.podcastsStorePaths = podcastsStorePaths
        self.podcastsPrefPaths = podcastsPrefPaths
        self.podcastsSurfacePresent = podcastsSurfacePresent
        self.notes = notes
    }
}


/// TV.app residual path plane (never dumps TV.app media caches or account material).
public struct TvAppPathPlaneState: Codable, Sendable, Equatable {
    public var tvAppPaths: [String]
    public var tvContainerPaths: [String]
    public var tvPrefPaths: [String]
    public var tvSurfacePresent: Bool?
    public var notes: [String]
    public init(
        tvAppPaths: [String] = [],
        tvContainerPaths: [String] = [],
        tvPrefPaths: [String] = [],
        tvSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.tvAppPaths = tvAppPaths
        self.tvContainerPaths = tvContainerPaths
        self.tvPrefPaths = tvPrefPaths
        self.tvSurfacePresent = tvSurfacePresent
        self.notes = notes
    }
}


/// HomeKit residual path plane (never enumerates HomeKit accessory secrets or pairs devices).
public struct HomekitPathPlaneState: Codable, Sendable, Equatable {
    public var homeAppPaths: [String]
    public var homeKitStorePaths: [String]
    public var homedPaths: [String]
    public var homekitSurfacePresent: Bool?
    public var notes: [String]
    public init(
        homeAppPaths: [String] = [],
        homeKitStorePaths: [String] = [],
        homedPaths: [String] = [],
        homekitSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.homeAppPaths = homeAppPaths
        self.homeKitStorePaths = homeKitStorePaths
        self.homedPaths = homedPaths
        self.homekitSurfacePresent = homekitSurfacePresent
        self.notes = notes
    }
}


/// Health app residual path plane (never exports HealthKit samples or medical records).
public struct HealthPathPlaneState: Codable, Sendable, Equatable {
    public var healthAppPaths: [String]
    public var healthStorePaths: [String]
    public var healthdPaths: [String]
    public var healthSurfacePresent: Bool?
    public var notes: [String]
    public init(
        healthAppPaths: [String] = [],
        healthStorePaths: [String] = [],
        healthdPaths: [String] = [],
        healthSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.healthAppPaths = healthAppPaths
        self.healthStorePaths = healthStorePaths
        self.healthdPaths = healthdPaths
        self.healthSurfacePresent = healthSurfacePresent
        self.notes = notes
    }
}


/// Wallet / pass residual path plane (never dumps pass contents, payment tokens, or card data).
public struct WalletPassPathState: Codable, Sendable, Equatable {
    public var walletAppPaths: [String]
    public var passesStorePaths: [String]
    public var passdPaths: [String]
    public var walletSurfacePresent: Bool?
    public var notes: [String]
    public init(
        walletAppPaths: [String] = [],
        passesStorePaths: [String] = [],
        passdPaths: [String] = [],
        walletSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.walletAppPaths = walletAppPaths
        self.passesStorePaths = passesStorePaths
        self.passdPaths = passdPaths
        self.walletSurfacePresent = walletSurfacePresent
        self.notes = notes
    }
}


/// Find My residual path plane (never queries Find My device locations or dumps owner tokens).
public struct FindmyPathPlaneState: Codable, Sendable, Equatable {
    public var findMyAppPaths: [String]
    public var findMyCachePaths: [String]
    public var fmfdPaths: [String]
    public var findmySurfacePresent: Bool?
    public var notes: [String]
    public init(
        findMyAppPaths: [String] = [],
        findMyCachePaths: [String] = [],
        fmfdPaths: [String] = [],
        findmySurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.findMyAppPaths = findMyAppPaths
        self.findMyCachePaths = findMyCachePaths
        self.fmfdPaths = fmfdPaths
        self.findmySurfacePresent = findmySurfacePresent
        self.notes = notes
    }
}


/// Shortcuts iCloud sync residual depth (never executes Shortcuts or dumps iCloud-synced automation databases).
public struct ShortcutsIcloudSyncState: Codable, Sendable, Equatable {
    public var shortcutsAppPaths: [String]
    public var shortcutsDbPaths: [String]
    public var shortcutsPrefPaths: [String]
    public var shortcutsIcloudSurfacePresent: Bool?
    public var notes: [String]
    public init(
        shortcutsAppPaths: [String] = [],
        shortcutsDbPaths: [String] = [],
        shortcutsPrefPaths: [String] = [],
        shortcutsIcloudSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.shortcutsAppPaths = shortcutsAppPaths
        self.shortcutsDbPaths = shortcutsDbPaths
        self.shortcutsPrefPaths = shortcutsPrefPaths
        self.shortcutsIcloudSurfacePresent = shortcutsIcloudSurfacePresent
        self.notes = notes
    }
}


/// Device management profile residual depth (never installs configuration profiles or enrolls hosts in MDM).
public struct DevicemanagementProfileState: Codable, Sendable, Equatable {
    public var profilesToolPaths: [String]
    public var managedPrefPaths: [String]
    public var mdmClientPaths: [String]
    public var deviceMgmtSurfacePresent: Bool?
    public var notes: [String]
    public init(
        profilesToolPaths: [String] = [],
        managedPrefPaths: [String] = [],
        mdmClientPaths: [String] = [],
        deviceMgmtSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.profilesToolPaths = profilesToolPaths
        self.managedPrefPaths = managedPrefPaths
        self.mdmClientPaths = mdmClientPaths
        self.deviceMgmtSurfacePresent = deviceMgmtSurfacePresent
        self.notes = notes
    }
}


/// Software Update catalog residual surface (never points SUS catalogs at attacker mirrors or tampers with update plists).
public struct SoftwareupdateCatalogState: Codable, Sendable, Equatable {
    public var softwareUpdateToolPaths: [String]
    public var softwareUpdatePrefPaths: [String]
    public var softwareUpdateDaemonPaths: [String]
    public var softwareUpdateSurfacePresent: Bool?
    public var notes: [String]
    public init(
        softwareUpdateToolPaths: [String] = [],
        softwareUpdatePrefPaths: [String] = [],
        softwareUpdateDaemonPaths: [String] = [],
        softwareUpdateSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.softwareUpdateToolPaths = softwareUpdateToolPaths
        self.softwareUpdatePrefPaths = softwareUpdatePrefPaths
        self.softwareUpdateDaemonPaths = softwareUpdateDaemonPaths
        self.softwareUpdateSurfacePresent = softwareUpdateSurfacePresent
        self.notes = notes
    }
}
