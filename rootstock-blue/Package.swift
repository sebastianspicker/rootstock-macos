// swift-tools-version: 6.2
// Target language mode 6. Host may run the best available Swift 6.x toolchain.
import PackageDescription

let package = Package(
    name: "RootstockBlue",
    platforms: [
        .macOS(.v14),
    ],
    products: [
        .library(name: "RootstockBlueCore", targets: ["RootstockBlueCore"]),
        .library(name: "RootstockBlueCase", targets: ["RootstockBlueCase"]),
        .library(name: "RootstockBlueSyntheticEvents", targets: ["RootstockBlueSyntheticEvents"]),
        .library(name: "RootstockBlueFX", targets: ["RootstockBlueFX"]),
        .library(name: "RootstockBlueDetect", targets: ["RootstockBlueDetect"]),
        .library(name: "RootstockBlueCollect", targets: ["RootstockBlueCollect"]),
        .library(name: "RootstockBlueExport", targets: ["RootstockBlueExport"]),
        .library(name: "RootstockBlueAcquire", targets: ["RootstockBlueAcquire"]),
        .library(name: "RootstockBlueIntegrations", targets: ["RootstockBlueIntegrations"]),
        .executable(name: "rootstock-blue", targets: ["rootstock-blue"]),
    ],
    dependencies: [
        .package(path: "../packages/RootstockMacFacts"),
    ],
    targets: [
        // MARK: - Core (no deps)
        .target(
            name: "RootstockBlueCore",
            path: "Packages/RootstockBlueCore/Sources/RootstockBlueCore",
            swiftSettings: strictConcurrencySettings
        ),

        // MARK: - Case package
        .target(
            name: "RootstockBlueCase",
            dependencies: ["RootstockBlueCore"],
            path: "Packages/RootstockBlueCase/Sources/RootstockBlueCase",
            swiftSettings: strictConcurrencySettings
        ),

        // MARK: - Synthetic event fixtures (no FX)
        .target(
            name: "RootstockBlueSyntheticEvents",
            dependencies: ["RootstockBlueCore"],
            path: "Packages/RootstockBlueSyntheticEvents/Sources/RootstockBlueSyntheticEvents",
            swiftSettings: strictConcurrencySettings
        ),

        // MARK: - Forensics (no ES)
        .target(
            name: "RootstockBlueFX",
            dependencies: [
                "RootstockBlueCore",
                .product(name: "RootstockMacFacts", package: "RootstockMacFacts"),
            ],
            path: "Packages/RootstockBlueFX/Sources/RootstockBlueFX",
            swiftSettings: strictConcurrencySettings
        ),

        // MARK: - Detections
        .target(
            name: "RootstockBlueDetect",
            dependencies: ["RootstockBlueCore"],
            path: "Packages/RootstockBlueDetect/Sources/RootstockBlueDetect",
            swiftSettings: strictConcurrencySettings
        ),

        // MARK: - Collect
        .target(
            name: "RootstockBlueCollect",
            dependencies: ["RootstockBlueCore", "RootstockBlueCase"],
            path: "Packages/RootstockBlueCollect/Sources/RootstockBlueCollect",
            swiftSettings: strictConcurrencySettings
        ),

        // MARK: - Export
        .target(
            name: "RootstockBlueExport",
            dependencies: [
                "RootstockBlueCore",
                "RootstockBlueCase",
                .product(name: "RootstockMacFacts", package: "RootstockMacFacts"),
            ],
            path: "Packages/RootstockBlueExport/Sources/RootstockBlueExport",
            swiftSettings: strictConcurrencySettings
        ),
        .testTarget(
            name: "RootstockBlueExportTests",
            dependencies: [
                "RootstockBlueExport",
                "RootstockBlueCase",
                "RootstockBlueFX",
                "RootstockBlueCore",
                "RootstockBlueDetect",
                "RootstockBlueCollect",
                "RootstockBlueAcquire",
                "RootstockBlueIntegrations",
                "RootstockBlueSyntheticEvents",
            ],
            path: "Tests/RootstockBlueExportTests",
            swiftSettings: strictConcurrencySettings
        ),

        // MARK: - Acquire
        .target(
            name: "RootstockBlueAcquire",
            dependencies: ["RootstockBlueCore", "RootstockBlueCase"],
            path: "Packages/RootstockBlueAcquire/Sources/RootstockBlueAcquire",
            swiftSettings: strictConcurrencySettings
        ),

        // MARK: - Integrations (do not reimplement)
        .target(
            name: "RootstockBlueIntegrations",
            dependencies: ["RootstockBlueCore"],
            path: "Packages/RootstockBlueIntegrations/Sources/RootstockBlueIntegrations",
            exclude: ["README.md"],
            swiftSettings: strictConcurrencySettings
        ),

        // MARK: - CLI
        .executableTarget(
            name: "rootstock-blue",
            dependencies: [
                "RootstockBlueCore",
                "RootstockBlueCase",
                "RootstockBlueSyntheticEvents",
                "RootstockBlueFX",
                "RootstockBlueDetect",
                "RootstockBlueCollect",
                "RootstockBlueExport",
                "RootstockBlueAcquire",
                "RootstockBlueIntegrations",
            ],
            path: "Packages/RootstockBlueCLI/Sources/rootstock-blue",
            swiftSettings: strictConcurrencySettings
        ),
    ],
    swiftLanguageModes: [.v6]
)

/// Complete strict concurrency for every product and test target (Swift 6 language mode default + explicit).
private let strictConcurrencySettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .enableUpcomingFeature("ExistentialAny"),
    .enableUpcomingFeature("InternalImportsByDefault"),
]
