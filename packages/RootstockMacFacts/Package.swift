// swift-tools-version: 6.0
import PackageDescription

/// Neutral macOS security vocabulary and read-only helpers shared by
/// collector, rootstock-red, and rootstock-blue.
///
/// Guardrails:
/// - No ScanResult / Finding / EventEnvelope types
/// - No Neo4j, case SQLite, or network
/// - No secret extraction
let package = Package(
    name: "RootstockMacFacts",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .library(name: "RootstockMacFacts", targets: ["RootstockMacFacts"]),
    ],
    targets: [
        .target(
            name: "RootstockMacFacts",
            path: "Sources/RootstockMacFacts"
        ),
        .testTarget(
            name: "RootstockMacFactsTests",
            dependencies: ["RootstockMacFacts"],
            path: "Tests/RootstockMacFactsTests"
        ),
    ]
)
