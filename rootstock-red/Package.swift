// swift-tools-version: 6.2
// Target language mode 6. Host may run best-available 6.x (6.2.4+).
import PackageDescription

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
        .library(name: "MacAgentKit", targets: ["MacAgentKit"]),
        .library(name: "MacTransportKit", targets: ["MacTransportKit"]),
        .library(name: "RootstockMythicAdapter", targets: ["RootstockMythicAdapter"]),
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

        // MARK: - Assess kits (default executable graph)
        .target(
            name: "MacOpsecKit",
            dependencies: ["RootstockCore"],
            path: "Sources/MacOpsecKit"
        ),
        .testTarget(
            name: "MacOpsecKitTests",
            dependencies: ["MacOpsecKit", "RootstockCore"],
            path: "Tests/MacOpsecKitTests"
        ),
        .target(
            name: "MacArtifactKit",
            dependencies: ["RootstockCore"],
            path: "Sources/MacArtifactKit"
        ),
        .target(
            name: "MacLolKit",
            dependencies: ["RootstockCore"],
            path: "Sources/MacLolKit",
            resources: [
                .process("Resources"),
            ]
        ),
        .target(
            name: "MacIdentityKit",
            dependencies: ["RootstockCore"],
            path: "Sources/MacIdentityKit"
        ),
        .target(
            name: "MacMdmKit",
            dependencies: ["RootstockCore"],
            path: "Sources/MacMdmKit"
        ),
        .target(
            name: "MacPersistKit",
            dependencies: [
                "RootstockCore",
                .product(name: "RootstockMacFacts", package: "RootstockMacFacts"),
            ],
            path: "Sources/MacPersistKit"
        ),
        .target(
            name: "MacEnumKit",
            dependencies: [
                "RootstockCore",
                "MacOpsecKit",
                "MacArtifactKit",
                "MacLolKit",
                "MacIdentityKit",
                "MacMdmKit",
                "MacPersistKit",
                .product(name: "RootstockMacFacts", package: "RootstockMacFacts"),
            ],
            path: "Sources/MacEnumKit"
        ),
        .testTarget(
            name: "MacEnumKitTests",
            dependencies: [
                "MacEnumKit",
                "RootstockCore",
                "MacIdentityKit",
                "MacMdmKit",
                "MacLolKit",
            ],
            path: "Tests/MacEnumKitTests"
        ),
        .target(
            name: "MacVulnKit",
            dependencies: ["RootstockCore", "MacEnumKit", "MacOpsecKit", "MacArtifactKit"],
            path: "Sources/MacVulnKit"
        ),
        .testTarget(
            name: "MacVulnKitTests",
            dependencies: [
                "MacVulnKit",
                "RootstockCore",
                "MacEnumKit",
                "MacOpsecKit",
                "MacArtifactKit",
                "MacReportKit",
            ],
            path: "Tests/MacVulnKitTests"
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
            name: "MacTransportKit",
            dependencies: ["RootstockCore"],
            path: "Sources/MacTransportKit"
        ),
        .target(
            name: "MacAgentKit",
            dependencies: ["RootstockCore", "MacTransportKit"],
            path: "Sources/MacAgentKit"
        ),
        .target(
            name: "RootstockLab",
            dependencies: ["RootstockCore"],
            path: "Sources/RootstockLab"
        ),
        .testTarget(
            name: "RootstockLabTests",
            dependencies: ["RootstockLab", "RootstockCore"],
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
        .target(
            name: "RootstockMythicAdapter",
            dependencies: ["RootstockCore"],
            path: "Sources/RootstockMythicAdapter"
        ),

        // MARK: - CLI (assess-only deps)
        .executableTarget(
            name: "RootstockRedCLI",
            dependencies: [
                "RootstockCore",
                "MacOpsecKit",
                "MacArtifactKit",
                "MacEnumKit",
                "MacVulnKit",
                "MacLolKit",
                "MacIdentityKit",
                "MacMdmKit",
                "MacPersistKit",
                "MacReportKit",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            path: "Sources/RootstockRedCLI"
        ),
    ],
    swiftLanguageModes: [.v6]
)
