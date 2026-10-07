// swift-tools-version: 6.2
// Target language mode 6. Host may run best-available 6.x (6.2.4+).
import PackageDescription
import Foundation

let package = Package(
    name: "RootstockRed",
    platforms: [
        .macOS(.v13),
    ],
    // Tools-version 6.2 defaults to Swift 6 language mode (strict concurrency).
    products: [
        .executable(name: "rootstock-red", targets: ["RootstockRedCLI"]),
        .executable(name: "rootstock-red-lab", targets: ["RootstockLabCLI"]),
        .library(name: "RootstockCore", targets: ["RootstockCore"]),
        .library(name: "MacEnumKit", targets: ["MacEnumKit"]),
        .library(name: "MacVulnKit", targets: ["MacVulnKit"]),
        .library(name: "MacReportKit", targets: ["MacReportKit"]),
        // Optional kits (not linked into default rootstock-red executable):
        .library(name: "RootstockLab", targets: ["RootstockLab"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.3.0"),
        .package(path: "../packages/RootstockMacFacts"),
    ],
    targets: [
        // MARK: - Core
        .target(
            name: "RootstockCore",
            dependencies: [],
            path: "Sources/RootstockCore"
        ),
        .testTarget(
            name: "RootstockCoreTests",
            dependencies: ["RootstockCore"],
            path: "Tests/RootstockCoreTests"
        ),

        // MARK: - Enumeration (default executable graph)
        .target(
            name: "MacEnumKit",
            dependencies: [
                "RootstockCore",
                .product(name: "RootstockMacFacts", package: "RootstockMacFacts"),
            ],
            path: "Sources/MacEnumKit",
            resources: [
                .process("LOLBins/Resources"),
            ]
        ),
        .testTarget(
            name: "MacEnumKitTests",
            dependencies: ["MacEnumKit"],
            path: "Tests/MacEnumKitTests"
        ),
        .target(
            name: "MacVulnKit",
            dependencies: ["RootstockCore", "MacEnumKit"],
            path: "Sources/MacVulnKit"
        ),
        .target(
            name: "MacReportKit",
            dependencies: ["RootstockCore"],
            path: "Sources/MacReportKit"
        ),
        .testTarget(
            name: "MacReportKitTests",
            dependencies: ["MacReportKit", "RootstockCore"],
            path: "Tests/MacReportKitTests"
        ),

        // MARK: - Optional (compile-only; not linked into rootstock-red)
        .target(
            name: "RootstockLab",
            dependencies: ["RootstockCore"],
            path: "Sources/RootstockLab"
        ),
        .testTarget(
            name: "RootstockLabTests",
            dependencies: ["RootstockCore", "RootstockLab"],
            path: "Tests/RootstockLabTests"
        ),
        .executableTarget(
            name: "RootstockLabCLI",
            dependencies: [
                "RootstockCore",
                "RootstockLab",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            path: "Sources/RootstockLabCLI"
        ),
        // MARK: - CLI (assess-only deps)
        .executableTarget(
            name: "RootstockRedCLI",
            dependencies: [
                "RootstockCore",
                "MacEnumKit",
                "MacVulnKit",
                "MacReportKit",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            path: "Sources/RootstockRedCLI"
        ),
    ].filter { target in
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        let path = root.appendingPathComponent(target.path ?? "Tests/\(target.name)").path
        return target.type != .test || FileManager.default.fileExists(atPath: path)
    },
    swiftLanguageModes: [.v6]
)
