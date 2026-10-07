// swift-tools-version: 6.2
// Target language mode 6. Host may run the best available Swift 6.x toolchain.
import PackageDescription
import Foundation

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
        .library(name: "RootstockBlueInterchange", targets: ["RootstockBlueInterchange"]),
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
            swiftSettings: strictConcurrencySettings
        ),

        // MARK: - Case package
        .target(
            name: "RootstockBlueCase",
            dependencies: ["RootstockBlueCore"],
            swiftSettings: strictConcurrencySettings
        ),

        // MARK: - Synthetic event fixtures (no FX)
        .target(
            name: "RootstockBlueSyntheticEvents",
            dependencies: ["RootstockBlueCore"],
            swiftSettings: strictConcurrencySettings
        ),

        // MARK: - Forensics (no ES)
        .target(
            name: "RootstockBlueFX",
            dependencies: [
                "RootstockBlueCore",
                .product(name: "RootstockMacFacts", package: "RootstockMacFacts"),
            ],
            swiftSettings: strictConcurrencySettings
        ),

        // MARK: - Detections
        .target(
            name: "RootstockBlueDetect",
            dependencies: ["RootstockBlueCore"],
            swiftSettings: strictConcurrencySettings
        ),

        // MARK: - Collect
        .target(
            name: "RootstockBlueCollect",
            dependencies: ["RootstockBlueCore", "RootstockBlueCase"],
            swiftSettings: strictConcurrencySettings
        ),

        // MARK: - Interchange (contract import/export + case outputs)
        .target(
            name: "RootstockBlueInterchange",
            dependencies: [
                "RootstockBlueCore",
                "RootstockBlueCase",
                .product(name: "RootstockMacFacts", package: "RootstockMacFacts"),
            ],
            swiftSettings: strictConcurrencySettings
        ),
        .testTarget(
            name: "RootstockBlueTests",
            dependencies: [
                "RootstockBlueInterchange",
                "RootstockBlueCase",
                "RootstockBlueFX",
                "RootstockBlueCore",
                "RootstockBlueDetect",
                "RootstockBlueCollect",
                "RootstockBlueAcquire",
                "RootstockBlueIntegrations",
                "RootstockBlueSyntheticEvents",
            ],
            exclude: ["Fixtures"],
            swiftSettings: strictConcurrencySettings
        ),

        // MARK: - Acquire
        .target(
            name: "RootstockBlueAcquire",
            dependencies: ["RootstockBlueCore", "RootstockBlueCase"],
            swiftSettings: strictConcurrencySettings
        ),

        // MARK: - Integrations (do not reimplement)
        .target(
            name: "RootstockBlueIntegrations",
            dependencies: ["RootstockBlueCore"],
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
                "RootstockBlueInterchange",
                "RootstockBlueIntegrations",
            ],
            swiftSettings: strictConcurrencySettings
        ),
    ].filter { target in
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        let path = root.appendingPathComponent(target.path ?? "Tests/\(target.name)").path
        return target.type != .test || FileManager.default.fileExists(atPath: path)
    },
    swiftLanguageModes: [.v6]
)

/// Complete strict concurrency for every product and test target (Swift 6 language mode default + explicit).
private let strictConcurrencySettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .enableUpcomingFeature("ExistentialAny"),
    .enableUpcomingFeature("InternalImportsByDefault"),
]
