// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "rootstock-collector",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(
            url: "https://github.com/apple/swift-argument-parser",
            exact: "1.6.2"
        ),
    ],
    targets: [
        .executableTarget(
            name: "RootstockCLI",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
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
            dependencies: ["Models"],
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
            dependencies: ["Models"]
        ),
        .target(
            name: "Persistence",
            dependencies: ["Models", "XPCServices"]
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
            name: "ModelsTests",
            dependencies: ["Models"]
        ),
        .testTarget(
            name: "TCCTests",
            dependencies: ["TCC", "Models"],
            linkerSettings: [.linkedLibrary("sqlite3")]
        ),
        .testTarget(
            name: "EntitlementTests",
            dependencies: ["Entitlements", "Models"],
            linkerSettings: [.linkedFramework("Security")]
        ),
        .testTarget(
            name: "CodeSigningTests",
            dependencies: ["CodeSigning", "Models"],
            linkerSettings: [.linkedFramework("Security")]
        ),
        .testTarget(
            name: "XPCTests",
            dependencies: ["XPCServices", "Models"],
            linkerSettings: [.linkedFramework("Security")]
        ),
        .testTarget(
            name: "PersistenceTests",
            dependencies: ["Persistence", "Models"]
        ),
        .testTarget(
            name: "KeychainTests",
            dependencies: ["Keychain", "Models"],
            linkerSettings: [.linkedFramework("Security")]
        ),
        .testTarget(
            name: "MDMTests",
            dependencies: ["MDM", "Models"]
        ),
        .testTarget(
            name: "ExportTests",
            dependencies: ["Export", "Models"]
        ),
        .testTarget(
            name: "GroupTests",
            dependencies: ["Groups", "Models"]
        ),
        .testTarget(
            name: "RemoteAccessTests",
            dependencies: ["RemoteAccess", "Models"]
        ),
        .testTarget(
            name: "FirewallTests",
            dependencies: ["Firewall", "Models"]
        ),
        .testTarget(
            name: "LoginSessionTests",
            dependencies: ["LoginSession", "Models"]
        ),
        .testTarget(
            name: "AuthorizationDBTests",
            dependencies: ["AuthorizationDB", "Models"]
        ),
        .testTarget(
            name: "AuthorizationPluginTests",
            dependencies: ["AuthorizationPlugins", "Models"]
        ),
        .testTarget(
            name: "SystemExtensionTests",
            dependencies: ["SystemExtensions", "Models"]
        ),
        .testTarget(
            name: "SudoersTests",
            dependencies: ["Sudoers", "Models"]
        ),
        .testTarget(
            name: "ProcessSnapshotTests",
            dependencies: ["ProcessSnapshot", "Models"]
        ),
        .testTarget(
            name: "FileACLTests",
            dependencies: ["FileACLs", "Models"]
        ),
        .testTarget(
            name: "ShellHookTests",
            dependencies: ["ShellHooks", "Models"]
        ),
        .testTarget(
            name: "PhysicalSecurityTests",
            dependencies: ["PhysicalSecurity", "Models"]
        ),
        .testTarget(
            name: "ActiveDirectoryTests",
            dependencies: ["ActiveDirectory", "Models"]
        ),
        .testTarget(
            name: "KerberosArtifactTests",
            dependencies: ["KerberosArtifacts", "Models"]
        ),
        .testTarget(
            name: "SandboxTests",
            dependencies: ["Sandbox", "Models"]
        ),
        .testTarget(
            name: "QuarantineTests",
            dependencies: ["Quarantine", "Models"]
        ),
    ]
)
