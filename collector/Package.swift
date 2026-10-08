// swift-tools-version: 6.3
import PackageDescription
import Foundation

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
                "HostCommand",
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
                "NetworkListeners",
                "TrustSettings",
                "BrowserExtensions",
                "InstalledPackages",
            ]
        ),
        .target(
            name: "Models",
            dependencies: []
        ),
        .target(
            name: "HostCommand",
            dependencies: []
        ),
        .target(
            name: "LaunchdPlists",
            dependencies: [
                "HostCommand",
                .product(name: "RootstockMacFacts", package: "RootstockMacFacts"),
            ]
        ),
        .target(
            name: "FileACLInspection",
            dependencies: ["Models", "HostCommand"]
        ),
        .target(
            name: "SQLiteSupport",
            dependencies: [],
            linkerSettings: [.linkedLibrary("sqlite3")]
        ),
        .target(
            name: "TCC",
            dependencies: [
                "Models",
                "SQLiteSupport",
                .product(name: "RootstockMacFacts", package: "RootstockMacFacts"),
            ]
        ),
        .target(
            name: "Entitlements",
            dependencies: ["Models", "HostCommand"],
            linkerSettings: [.linkedFramework("Security")]
        ),
        .target(
            name: "CodeSigning",
            dependencies: ["Models", "HostCommand"],
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
                "HostCommand",
                "LaunchdPlists",
                .product(name: "RootstockMacFacts", package: "RootstockMacFacts"),
            ]
        ),
        .target(
            name: "Persistence",
            dependencies: [
                "Models",
                "HostCommand",
                "LaunchdPlists",
                .product(name: "RootstockMacFacts", package: "RootstockMacFacts"),
            ],
            linkerSettings: [.linkedFramework("Security")]
        ),
        .target(
            name: "Keychain",
            dependencies: ["Models"],
            linkerSettings: [.linkedFramework("Security")]
        ),
        .target(
            name: "MDM",
            dependencies: [
                "Models",
                "HostCommand",
                .product(name: "RootstockMacFacts", package: "RootstockMacFacts"),
            ]
        ),
        .target(
            name: "Groups",
            dependencies: ["Models", "HostCommand"]
        ),
        .target(
            name: "RemoteAccess",
            dependencies: ["Models", "HostCommand"]
        ),
        .target(
            name: "Firewall",
            dependencies: ["Models", "HostCommand"]
        ),
        .target(
            name: "LoginSession",
            dependencies: ["Models", "HostCommand"]
        ),
        .target(
            name: "AuthorizationDB",
            dependencies: ["Models", "HostCommand"]
        ),
        .target(
            name: "AuthorizationPlugins",
            dependencies: [
                "Models",
                "HostCommand",
                .product(name: "RootstockMacFacts", package: "RootstockMacFacts"),
            ]
        ),
        .target(
            name: "SystemExtensions",
            dependencies: ["Models", "HostCommand"]
        ),
        .target(
            name: "Sudoers",
            dependencies: [
                "Models",
                .product(name: "RootstockMacFacts", package: "RootstockMacFacts"),
            ]
        ),
        .target(
            name: "ProcessSnapshot",
            dependencies: ["Models", "HostCommand"]
        ),
        .target(
            name: "FileACLs",
            dependencies: [
                "Models",
                "FileACLInspection",
                .product(name: "RootstockMacFacts", package: "RootstockMacFacts"),
            ]
        ),
        .target(
            name: "ShellHooks",
            dependencies: ["Models", "FileACLInspection"]
        ),
        .target(
            name: "PhysicalSecurity",
            dependencies: ["Models", "HostCommand"]
        ),
        .target(
            name: "ActiveDirectory",
            dependencies: ["Models", "HostCommand"]
        ),
        .target(
            name: "KerberosArtifacts",
            dependencies: [
                "Models",
                .product(name: "RootstockMacFacts", package: "RootstockMacFacts"),
            ]
        ),
        .target(
            name: "Sandbox",
            dependencies: ["Models"]
        ),
        .target(
            name: "Quarantine",
            dependencies: ["Models", "SQLiteSupport"]
        ),
        .target(
            name: "NetworkListeners",
            dependencies: ["Models", "HostCommand"]
        ),
        .target(
            name: "TrustSettings",
            dependencies: ["Models"],
            linkerSettings: [.linkedFramework("Security"), .linkedFramework("CryptoKit")]
        ),
        .target(
            name: "BrowserExtensions",
            dependencies: ["Models", "HostCommand"]
        ),
        .target(
            name: "InstalledPackages",
            dependencies: ["Models", "HostCommand"]
        ),
        .testTarget(
            name: "ExportTests",
            dependencies: ["Export", "Models"]
        ),
        .testTarget(
            name: "RootstockCLITests",
            dependencies: ["RootstockCLI", "Models", "Export", "HostCommand"]
        ),
        .testTarget(
            name: "SandboxTests",
            dependencies: ["Sandbox"]
        ),
        .testTarget(
            name: "NetworkListenersTests",
            dependencies: ["NetworkListeners", "Models"]
        ),
        .testTarget(
            name: "BrowserExtensionsTests",
            dependencies: ["BrowserExtensions", "Models"]
        ),
        .testTarget(
            name: "InstalledPackagesTests",
            dependencies: ["InstalledPackages", "Models"]
        ),
        .testTarget(
            name: "PersistenceTests",
            dependencies: ["Persistence", "LaunchdPlists", "Models"]
        ),
        .testTarget(
            name: "ProcessSnapshotTests",
            dependencies: ["ProcessSnapshot", "Models"]
        ),
        .testTarget(
            name: "RemoteAccessTests",
            dependencies: ["RemoteAccess"]
        ),
        .testTarget(
            name: "EntitlementsTests",
            dependencies: ["Entitlements"]
        ),
    ].filter { target in
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        let path = root.appendingPathComponent(target.path ?? "Tests/\(target.name)").path
        return target.type != .test || FileManager.default.fileExists(atPath: path)
    },
    swiftLanguageModes: [.v6]
)
