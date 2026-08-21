// swift-tools-version: 6.3
import PackageDescription

let package = Package(
    name: "rootstock-collector",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "RootstockCLI", targets: ["RootstockCLI"]),
    ],
    dependencies: [
        .package(
            url: "https://github.com/apple/swift-argument-parser",
            exact: "1.6.2"
        ),
        .package(path: "../packages/RootstockMacFacts"),
    ],
    targets: [
        .executableTarget(
            name: "RootstockCLI",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "RootstockMacFacts", package: "RootstockMacFacts"),
                "Models",
                "TCC",
                "Entitlements",
                "CodeSigning",
                "Export",
                "XPCServices",
                "Persistence",
                "Keychain",
                "MDM",
                "Groups",
                "RemoteAccess",
                "Firewall",
                "LoginSession",
                "AuthorizationDB",
                "AuthorizationPlugins",
                "SystemExtensions",
                "Sudoers",
                "ProcessSnapshot",
                "FileACLs",
                "ShellHooks",
                "PhysicalSecurity",
                "ActiveDirectory",
                "KerberosArtifacts",
                "Sandbox",
                "Quarantine",
            ]
        ),
        .target(
            name: "Models",
            dependencies: []
        ),
        .target(
            name: "TCC",
            dependencies: [
                "Models",
                .product(name: "RootstockMacFacts", package: "RootstockMacFacts"),
            ],
            linkerSettings: [.linkedLibrary("sqlite3")]
        ),
        .target(
            name: "Entitlements",
            dependencies: ["Models"],
            linkerSettings: [.linkedFramework("Security")]
        ),
        .target(
            name: "CodeSigning",
            dependencies: ["Models"],
            linkerSettings: [.linkedFramework("Security")]
        ),
        .target(
            name: "Export",
            dependencies: ["Models"]
        ),
        .target(
            name: "XPCServices",
            dependencies: [
                "Models",
                .product(name: "RootstockMacFacts", package: "RootstockMacFacts"),
            ]
        ),
        .target(
            name: "Persistence",
            dependencies: [
                "Models",
                "XPCServices",
                .product(name: "RootstockMacFacts", package: "RootstockMacFacts"),
            ]
        ),
        .target(
            name: "Keychain",
            dependencies: ["Models"],
            linkerSettings: [.linkedFramework("Security")]
        ),
        .target(
            name: "MDM",
            dependencies: ["Models"]
        ),
        .target(
            name: "Groups",
            dependencies: ["Models"]
        ),
        .target(
            name: "RemoteAccess",
            dependencies: ["Models"]
        ),
        .target(
            name: "Firewall",
            dependencies: ["Models"]
        ),
        .target(
            name: "LoginSession",
            dependencies: ["Models"]
        ),
        .target(
            name: "AuthorizationDB",
            dependencies: ["Models"]
        ),
        .target(
            name: "AuthorizationPlugins",
            dependencies: ["Models"]
        ),
        .target(
            name: "SystemExtensions",
            dependencies: ["Models"]
        ),
        .target(
            name: "Sudoers",
            dependencies: ["Models"]
        ),
        .target(
            name: "ProcessSnapshot",
            dependencies: ["Models"]
        ),
        .target(
            name: "FileACLs",
            dependencies: ["Models"]
        ),
        .target(
            name: "ShellHooks",
            dependencies: ["Models", "FileACLs"]
        ),
        .target(
            name: "PhysicalSecurity",
            dependencies: ["Models"]
        ),
        .target(
            name: "ActiveDirectory",
            dependencies: ["Models"]
        ),
        .target(
            name: "KerberosArtifacts",
            dependencies: ["Models"]
        ),
        .target(
            name: "Sandbox",
            dependencies: ["Models"]
        ),
        .target(
            name: "Quarantine",
            dependencies: ["Models"]
        ),
        .testTarget(
            name: "ExportTests",
            dependencies: ["Export", "Models"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
