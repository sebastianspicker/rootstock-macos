import Testing
import Foundation
@testable import Export
@testable import Models

/// Golden-fixture check for the legacy collector wire format.
///
/// Builds a synthetic `ScanResult` in which every optional field and every nested
/// type is populated, encodes it with the real `JSONExporter`, and requires the
/// JSON document to equal the checked-in fixture
/// `contracts/collector-scan/fixtures/valid-collector-encoder-complete.json`.
/// Both sides are normalized (sorted keys, compact) before comparison so that
/// Foundation pretty-printing differences between toolchains are not contract drift;
/// key names, nesting, values and JSON types still must match exactly.
/// `scripts/check-contracts.py` validates that same fixture against the
/// canonical schema, so the chain proves real encoder output conforms.
///
/// Regenerate after an intentional contract change (from `collector/`):
///
///     ROOTSTOCK_REGENERATE_FIXTURES=1 swift test --filter CompleteScanFixtureTests
@Suite struct CompleteScanFixtureTests {

    static let fixtureURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()  // ExportTests
        .deletingLastPathComponent()  // Tests
        .deletingLastPathComponent()  // collector
        .deletingLastPathComponent()  // repository root
        .appendingPathComponent("contracts/collector-scan/fixtures/valid-collector-encoder-complete.json")

    @Test func encoderOutputMatchesCompleteFixture() throws {
        var actual = try JSONExporter().encode(CompleteScanFixture.make())
        actual.append(0x0A)

        if ProcessInfo.processInfo.environment["ROOTSTOCK_REGENERATE_FIXTURES"] == "1" {
            try actual.write(to: Self.fixtureURL)
            print("Regenerated \(Self.fixtureURL.path)")
            return
        }

        let expected = try Data(contentsOf: Self.fixtureURL)
        guard try Self.normalized(actual) != Self.normalized(expected) else { return }

        let actualURL = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("valid-collector-encoder-complete.actual.json")
        try actual.write(to: actualURL)
        Issue.record("""
            Collector encoder output differs from \(Self.fixtureURL.path).
            Actual output written to \(actualURL.path).
            If the wire-format change is intentional, regenerate from collector/ with:
              ROOTSTOCK_REGENERATE_FIXTURES=1 swift test --filter CompleteScanFixtureTests
            and run scripts/check-contracts.py against the updated schema.
            """)
    }

    private static func normalized(_ json: Data) throws -> Data {
        let document = try JSONSerialization.jsonObject(with: json, options: [.fragmentsAllowed])
        return try JSONSerialization.data(
            withJSONObject: document,
            options: [.sortedKeys, .fragmentsAllowed, .withoutEscapingSlashes]
        )
    }
}

/// Synthetic, fictional host data only.
enum CompleteScanFixture {
    static func make() -> ScanResult {
        ScanResult(
            metadata: ScanResult.Metadata(
                scanId: "fixture-complete-acme-macbook-pro",
                timestamp: "2026-03-20T10:00:00Z",
                hostname: "acme-macbook-pro",
                macosVersion: "macOS 15.3 (Build 24D60)",
                collectorVersion: "0.0.0-fixture"
            ),
            elevation: ElevationInfo(isRoot: true, hasFda: false),
            collections: ScanResult.Collections(
                core: coreCollections(),
                accountAccess: accountAccessCollections(),
                system: systemCollections()
            ),
            hostPosture: hostPosture(),
            errors: [
                CollectionError(source: "Acme Source", message: "synthetic recoverable error", recoverable: true),
            ]
        )
    }

    // MARK: - Core

    private static func coreCollections() -> ScanResult.CoreCollections {
        ScanResult.CoreCollections(
            applications: [application()],
            tccGrants: [
                TCCGrant(
                    service: "kTCCServiceSystemPolicyAllFiles",
                    displayName: "Full Disk Access",
                    client: "com.acme.widget",
                    clientType: 0,
                    authValue: 2,
                    authReason: 4,
                    scope: "user",
                    lastModified: 1_742_464_800
                ),
            ],
            xpcServices: [XPCService.ServiceType.daemon, .agent].map { type in
                XPCService(
                    label: "com.acme.widget.helper.\(type.rawValue)",
                    path: "/Library/LaunchDaemons/com.acme.widget.helper.\(type.rawValue).plist",
                    program: "/Library/PrivilegedHelperTools/com.acme.widget.helper",
                    type: type,
                    launch: XPCService.LaunchBehavior(user: "root", runAtLoad: true, keepAlive: true),
                    exposure: XPCService.Exposure(
                        machServices: ["com.acme.widget.helper.xpc"],
                        entitlements: ["com.apple.private.acme-fixture"],
                        hasClientVerification: true
                    )
                )
            },
            keychainAcls: keychainItems(),
            mdmProfiles: [
                MDMProfile(
                    identifier: "com.acme.mdm.pppc",
                    displayName: "Acme Privacy Preferences",
                    organization: "Acme Corp",
                    installDate: "2026-01-15 09:30:00 +0000",
                    tccPolicies: [
                        TCCPolicy(service: "SystemPolicyAllFiles", clientBundleId: "com.acme.widget", allowed: true),
                    ]
                ),
            ],
            launchItems: launchItems()
        )
    }

    private static func keychainItems() -> [KeychainItem] {
        [
            KeychainItem.Kind.genericPassword, .internetPassword, .certificate, .key,
        ].map { kind in
            KeychainItem(
                label: "Acme Fixture \(kind.rawValue)",
                kind: kind,
                service: "com.acme.widget.sync",
                accessGroup: "ACME123456.com.acme.widget",
                trustedApps: ["com.acme.widget"]
            )
        }
    }

    private static func launchItems() -> [LaunchItem] {
        [
            LaunchItem.ItemType.daemon, .agent, .loginItem, .cron,
        ].map { type in
            LaunchItem(
                label: "com.acme.widget.\(type.rawValue)",
                path: "/Library/LaunchDaemons/com.acme.widget.\(type.rawValue).plist",
                type: type,
                program: "/Applications/AcmeWidget.app/Contents/MacOS/AcmeWidget",
                runAtLoad: true,
                user: "acme-admin",
                ownership: LaunchItem.Ownership(
                    plistOwner: "root",
                    programOwner: "acme-admin",
                    plistWritableByNonRoot: false,
                    programWritableByNonRoot: true
                )
            )
        }
    }

    private static func application() -> Application {
        Application(
            identity: Application.Identity(
                name: "AcmeWidget",
                bundleId: "com.acme.widget",
                path: "/Applications/AcmeWidget.app",
                version: "4.2.0"
            ),
            flags: Application.Flags(isElectron: true, isSystem: false),
            signing: Application.Signing(
                teamId: "ACME123456",
                hardenedRuntime: false,
                libraryValidation: false,
                signed: true,
                analysis: Application.SigningAnalysis(
                    codeSigningAnalysisError: false,
                    isNotarized: true,
                    isAdhocSigned: false
                ),
                certificate: certificateState()
            ),
            security: Application.Security(
                isSipProtected: false,
                isSandboxed: true,
                sandboxExceptions: ["com.apple.security.temporary-exception.files.absolute-path.read-write"]
            ),
            entitlementState: Application.EntitlementState(
                entitlementsAvailable: true,
                entitlementExtractionError: "synthetic partial extraction warning",
                entitlements: [
                    EntitlementInfo(
                        name: "com.apple.security.cs.allow-dyld-environment-variables",
                        isPrivate: false,
                        category: "injection",
                        isSecurityCritical: true
                    ),
                ],
                injectionMethods: [
                    .dyldInsert, .dyldInsertViaEntitlement, .missingLibraryValidation, .electronEnvVar,
                ],
                launchConstraintCategory: "acme-fixture-category"
            ),
            sandboxProfile: sandboxProfile(),
            quarantineInfo: QuarantineInfo(
                hasQuarantineFlag: true,
                quarantineAgent: "com.acme.browser",
                quarantineTimestamp: "2026-02-01T08:00:00Z",
                wasUserApproved: true,
                wasTranslocated: true
            )
        )
    }

    private static func certificateState() -> Application.CertificateState {
        Application.CertificateState(
            signingCertificateCN: "Developer ID Application: Acme Corp (ACME123456)",
            signingCertificateSHA256: String(repeating: "ab", count: 32),
            certificateExpires: "2030-06-15T00:00:00Z",
            isCertificateExpired: false,
            certificateChainLength: 2,
            certificateTrustValid: true,
            certificateChain: [
                CertificateDetail(
                    commonName: "Developer ID Application: Acme Corp (ACME123456)",
                    organization: "Acme Corp",
                    sha256: String(repeating: "ab", count: 32),
                    validFrom: "2025-06-15T00:00:00Z",
                    validTo: "2030-06-15T00:00:00Z",
                    isRoot: false
                ),
                CertificateDetail(
                    commonName: "Acme Fixture Root CA",
                    organization: "Acme Fixture Trust",
                    sha256: String(repeating: "cd", count: 32),
                    validFrom: "2020-01-01T00:00:00Z",
                    validTo: "2040-01-01T00:00:00Z",
                    isRoot: true
                ),
            ]
        )
    }

    private static func sandboxProfile() -> SandboxProfile {
        SandboxProfile(
            bundleId: "com.acme.widget",
            profileSource: "entitlements",
            rules: SandboxProfile.Rules(
                fileReadRules: ["/Users/acme-admin/Documents"],
                fileWriteRules: ["/Users/acme-admin/Downloads"],
                machLookupRules: ["com.acme.widget.helper.xpc"],
                networkRules: ["network-client"],
                iokitRules: ["IOUSBDevice"]
            ),
            exposure: SandboxProfile.Exposure(
                exceptionCount: 1,
                hasUnconstrainedNetwork: true,
                hasUnconstrainedFileRead: true
            )
        )
    }

    // MARK: - Account and access

    private static func accountAccessCollections() -> ScanResult.AccountAccessCollections {
        ScanResult.AccountAccessCollections(
            localGroups: [LocalGroup(name: "admin", gid: 80, members: ["acme-admin"])],
            remoteAccessServices: [
                RemoteAccessService(
                    service: RemoteServiceName.ssh,
                    enabled: true,
                    port: 22,
                    config: ["PasswordAuthentication": "no", "PermitRootLogin": "no"]
                ),
                RemoteAccessService(service: RemoteServiceName.screenSharing, enabled: false, port: 5900, config: [:]),
            ],
            firewallStatus: [
                FirewallStatus(
                    enabled: true,
                    stealthMode: false,
                    allowSigned: true,
                    allowBuiltIn: true,
                    appRules: [FirewallAppRule(bundleId: "com.acme.widget", allowIncoming: true)]
                ),
            ],
            loginSessions: [
                LoginSession.SessionType.console, .ssh, .screenSharing, .tmux,
            ].map { type in
                LoginSession(
                    username: "acme-admin",
                    terminal: "ttys-\(type.rawValue)",
                    loginTime: "Mar 20 09:00",
                    sessionType: type
                )
            },
            authorization: ScanResult.AuthorizationCollections(
                authorizationRights: [
                    AuthorizationRight(
                        name: "system.privilege.admin",
                        rule: "authenticate-admin-nonshared",
                        allowRoot: true,
                        requireAuthentication: true
                    ),
                ],
                authorizationPlugins: [
                    AuthorizationPlugin(
                        name: "AcmeAuthPlugin",
                        path: "/Library/Security/SecurityAgentPlugins/AcmeAuthPlugin.bundle",
                        teamId: "ACME123456"
                    ),
                ],
                systemExtensions: systemExtensions()
            ),
            sudoersRules: [
                SudoersRule(user: "%admin", host: "ALL", command: "/usr/bin/acme-widget-cli", nopasswd: true),
            ]
        )
    }

    private static func systemExtensions() -> [SystemExtension] {
        [SystemExtension.ExtensionType.network, .endpointSecurity, .driver].map { type in
            SystemExtension(
                identifier: "com.acme.widget.extension.\(type.rawValue)",
                teamId: "ACME123456",
                extensionType: type,
                enabled: true,
                subscribedEvents: ["ES_EVENT_TYPE_NOTIFY_EXEC"]
            )
        }
    }

    // MARK: - System

    private static func systemCollections() -> ScanResult.SystemCollections {
        ScanResult.SystemCollections(
            runningProcesses: [
                RunningProcess(
                    pid: 4242,
                    user: "acme-admin",
                    command: "/Applications/AcmeWidget.app/Contents/MacOS/AcmeWidget",
                    bundleId: "com.acme.widget"
                ),
            ],
            userDetails: [
                UserDetail(name: "acme-admin", shell: "/bin/zsh", homeDir: "/Users/acme-admin", isHidden: false, isADUser: true),
            ],
            fileAcls: [
                FileACL(
                    path: "/Library/Application Support/com.apple.TCC/TCC.db",
                    owner: "root",
                    group: "wheel",
                    mode: "644",
                    aclEntries: ["group:everyone deny delete"],
                    isSipProtected: false,
                    isWritableByNonRoot: false,
                    category: "tcc_database"
                ),
            ],
            bluetoothDevices: [
                BluetoothDevice(name: "Acme Keyboard", address: "00-11-22-33-44-55", deviceType: "keyboard", connected: true),
            ],
            adBinding: ADBinding(
                isBound: true,
                realm: "CORP.ACME.EXAMPLE",
                forest: "corp.acme.example",
                computerAccount: "acme-macbook-pro$",
                organizationalUnit: "OU=Macs,DC=corp,DC=acme,DC=example",
                preferredDC: "dc01.corp.acme.example",
                groupMappings: [ADGroupMapping(adGroup: "Domain Admins", localGroup: "admin")]
            ),
            kerberosArtifacts: kerberosArtifacts(),
            sandboxProfiles: [sandboxProfile()]
        )
    }

    private static func kerberosArtifacts() -> [KerberosArtifact] {
        [KerberosArtifactType.ccache, .keytab, .config].map { type in
            KerberosArtifact(
                path: "/var/db/acme-fixture/\(type.rawValue)",
                artifactType: type,
                metadata: KerberosArtifact.FileMetadata(
                    owner: "acme-admin",
                    group: "staff",
                    mode: "600",
                    modificationTime: "2026-03-19T12:00:00Z",
                    principalHint: "acme-admin"
                ),
                readability: KerberosArtifact.Readability(
                    isReadable: true,
                    isWorldReadable: false,
                    isGroupReadable: false
                ),
                config: KerberosArtifact.ConfigFields(
                    defaultRealm: "CORP.ACME.EXAMPLE",
                    permittedEncTypes: ["aes256-cts-hmac-sha1-96"],
                    realmNames: ["CORP.ACME.EXAMPLE"],
                    isForwardable: true
                )
            )
        }
    }

    // MARK: - Host posture

    private static func hostPosture() -> ScanResult.HostPosture {
        ScanResult.HostPosture(
            gatekeeperEnabled: true,
            sipEnabled: true,
            filevaultEnabled: true,
            physicalSecurity: ScanResult.PhysicalSecurity(
                device: ScanResult.DeviceSecurity(
                    lockdownModeEnabled: false,
                    bluetoothEnabled: true,
                    bluetoothDiscoverable: false
                ),
                screen: ScanResult.ScreenSecurity(
                    screenLockEnabled: true,
                    screenLockDelay: 5,
                    displaySleepTimeout: 10
                ),
                boot: ScanResult.BootSecurity(
                    thunderboltSecurityLevel: "secure",
                    secureBootLevel: "full",
                    externalBootAllowed: false
                )
            ),
            icloud: ScanResult.ICloud(
                icloudSignedIn: true,
                icloudDriveEnabled: true,
                icloudKeychainEnabled: false
            )
        )
    }
}
