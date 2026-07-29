import XCTest
import RootstockCore
import MacEnumKit
import MacArtifactKit
@testable import MacVulnKit

extension AttackVectorTests {
    static func syntheticWeakState() -> CollectedState {
        var state = CollectedState()
        configureFixtureCore(&state)
        configureFixtureWave3To6(&state)
        configureFixtureWave7To8(&state)
        configureFixtureWave9To11(&state)
        configureFixtureWave12To14(&state)
        configureFixtureWave15To16(&state)
        configureFixtureAmplifiers(&state)
        return state
    }

    static func configureFixtureCore(_ state: inout CollectedState) {
        configureFixtureCorePart1(&state)
        configureFixtureCorePart2(&state)
        configureFixtureCorePart3(&state)
    }
    static func configureFixtureCorePart1(_ state: inout CollectedState) {
        configureFixtureCorePart1Segment1(&state)
        configureFixtureCorePart1Segment2(&state)
    }

    static func configureFixtureCorePart1Segment1(_ state: inout CollectedState) {
        configureFixtureCorePart1Segment1Leaf1(&state)
        configureFixtureCorePart1Segment1Leaf2(&state)
    }

    static func configureFixtureCorePart1Segment1Leaf1(_ state: inout CollectedState) {



        state.host = HostState(
            hostname: "vector-test",
            username: "tester",
            osVersion: "14.5.0",
            arch: "arm64",
            processArch: "arm64",
            isRoot: false
        )
        state.protections = ProtectionsState(
            sipEnabled: false,
            gatekeeperEnabled: false,
            fileVaultOn: true,
            notes: ["synthetic: SIP and Gatekeeper off"]
        )
        state.launchAgents = [
            LaunchAgentEntry(
                label: "com.example.agent",
                path: NSHomeDirectory() + "/Library/LaunchAgents/com.example.agent.plist",
                programArguments: ["/usr/bin/true"]
            ),
        ]
    }

    static func configureFixtureCorePart1Segment1Leaf2(_ state: inout CollectedState) {
        state.loginItems = LoginItemsState(
            btmStorePresent: true,
            btmDirectoryPath: NSHomeDirectory() + "/Library/Application Support/com.apple.backgroundtaskmanagementagent",
            notes: ["synthetic BTM present"]
        )
        state.injectabilityHits = [
            InjectabilityHit(
                path: "/tmp/debug.app/Contents/MacOS/debug",
                hardenedRuntime: false,
                getTaskAllow: true,
                disableLibraryValidation: true,
                riskFlags: ["hardened_runtime_off", "get-task-allow", "disable-library-validation"]
            ),
        ]
        }

    static func configureFixtureCorePart1Segment2(_ state: inout CollectedState) {
        configureFixtureCorePart1Segment2Leaf1(&state)
        configureFixtureCorePart1Segment2Leaf2(&state)
    }

    static func configureFixtureCorePart1Segment2Leaf1(_ state: inout CollectedState) {

        state.dylibRiskHits = [
            DylibRiskHit(
                path: "/tmp/debug.app/Contents/MacOS/debug",
                weakDylibs: ["@rpath/libEvil.dylib"],
                notes: ["synthetic weak dylib"]
            ),
        ]
        state.credPaths = [
            CredPathHit(kind: "ssh", path: NSHomeDirectory() + "/.ssh/id_rsa", exists: true),
            CredPathHit(kind: "aws", path: NSHomeDirectory() + "/.aws/credentials", exists: true),
        ]
        state.identity = IdentityState(
            adBound: true,
            platformSSO: true,
            kerberosConfigPresent: true,
            odConfigPaths: ["/Library/Preferences/OpenDirectory/Configurations/Active Directory"],
            ssoPaths: ["/Library/Application Support/com.apple.AppSSOAgent"],
            notes: ["synthetic AD-bound + Platform SSO"]
        )
        // Explicit empty EDR path hits so security_product_gap / identity_edr cluster can fire.
        state.securityProducts = [
            SecurityProductHit(name: "SyntheticEDR", path: "/Applications/SyntheticEDR.app", present: false),
        ]
    }

    static func configureFixtureCorePart1Segment2Leaf2(_ state: inout CollectedState) {
        state.loobins = [
            LOOBinHit(name: "osascript", path: "/usr/bin/osascript", present: true, tactics: ["execution"]),
            LOOBinHit(name: "launchctl", path: "/bin/launchctl", present: true, tactics: ["persistence", "execution"]),
            LOOBinHit(name: "system_profiler", path: "/usr/sbin/system_profiler", present: true, tactics: ["discovery"]),
            LOOBinHit(name: "mdfind", path: "/usr/bin/mdfind", present: true, tactics: ["discovery"]),
        ]
            }

    static func configureFixtureCorePart2(_ state: inout CollectedState) {
        configureFixtureCorePart2Segment1(&state)
        configureFixtureCorePart2Segment2(&state)
    }

    static func configureFixtureCorePart2Segment1(_ state: inout CollectedState) {
        configureFixtureCorePart2Segment1Leaf1(&state)
        configureFixtureCorePart2Segment1Leaf2(&state)
    }

    static func configureFixtureCorePart2Segment1Leaf1(_ state: inout CollectedState) {


    }

    static func configureFixtureCorePart2Segment1Leaf2(_ state: inout CollectedState) {
        state.lolPlans = [
            LOLPlanEntry(
                name: "system_profiler",
                path: "/usr/sbin/system_profiler",
                goal: "discovery",
                noiseScore: 15,
                rankReason: "discovery: system_profiler low noise"
            ),
            LOLPlanEntry(
                name: "mdfind",
                path: "/usr/bin/mdfind",
                goal: "discovery",
                noiseScore: 40,
                rankReason: "discovery: mdfind medium noise"
            ),
            LOLPlanEntry(
                name: "launchctl",
                path: "/bin/launchctl",
                goal: "persist",
                noiseScore: 50,
                rankReason: "persist: launchctl medium noise"
            ),
            LOLPlanEntry(
                name: "osascript",
                path: "/usr/bin/osascript",
                goal: "execute",
                noiseScore: 85,
                tccImpact: ["Automation"],
                rankReason: "execute: osascript very high noise"
            ),
        ]
        }

    static func configureFixtureCorePart2Segment2(_ state: inout CollectedState) {
        configureFixtureCorePart2Segment2Leaf1(&state)
        configureFixtureCorePart2Segment2Leaf2(&state)
    }

    static func configureFixtureCorePart2Segment2Leaf1(_ state: inout CollectedState) {

        state.network = NetworkState(reachability: .init(remoteLoginSSH: true, screenSharingARD: true, fileSharingSMB: true), artifacts: .init(remoteLoginPlistPresent: true, screenSharingPlistPresent: true, sshdConfigPresent: true), notes: ["synthetic remote access enabled"])
        // Expanded vectors: TCC/FDA, browser session, helpers/sygext, MDM gap, PEASS paths.
        state.tcc = TCCState(
            fullDiskAccessLikely: true,
            notes: ["synthetic FDA path listability"],
            probeMethod: "synthetic"
        )
    }

    static func configureFixtureCorePart2Segment2Leaf2(_ state: inout CollectedState) {
        state.browserMeta = [
            BrowserMetaEntry(
                browser: "Chrome",
                kind: "cookies",
                path: NSHomeDirectory() + "/Library/Application Support/Google/Chrome/Default/Cookies",
                exists: true,
                sizeBytes: 4096
            ),
            BrowserMetaEntry(
                browser: "Chrome",
                kind: "login_data",
                path: NSHomeDirectory() + "/Library/Application Support/Google/Chrome/Default/Login Data",
                exists: true,
                sizeBytes: 2048
            ),
        ]
        state.privilegedHelperTools = [
            "/tmp/rootstock-red-synthetic/PrivilegedHelperTools/com.example.helper",
        ]
        state.systemExtensionPaths = [
            "/tmp/rootstock-red-synthetic/SystemExtensions/com.example.ext.systemextension",
        ]
            }

    static func configureFixtureCorePart3(_ state: inout CollectedState) {
        state.mdm = MDMState(
            enrolled: false,
            vendorHints: [],
            managedPreferenceNames: [],
            profileStoreReadable: false,
            profileFileCount: 0,
            pppcPolicyPresent: false,
            notes: ["synthetic unmanaged host"]
        )
        // PEASS-class writable privileged paths via collector note (forceWritable) + real temp file.
        let tmpRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("rootstock-red-privesc-synth-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: tmpRoot, withIntermediateDirectories: true)
        let fakeDaemon = tmpRoot.appendingPathComponent("com.example.evil.plist")
        try? Data("synthetic".utf8).write(to: fakeDaemon)
        state.launchDaemons = [
            LaunchAgentEntry(
                label: "com.example.evil",
                path: fakeDaemon.path,
                programArguments: ["/usr/bin/true"]
            ),
        ]
        state.collectorNotes["privesc.writable_paths"] = fakeDaemon.path
        }


    static func configureFixtureWave3To6(_ state: inout CollectedState) {
        configureFixtureWave3To6Part1(&state)
        configureFixtureWave3To6Part2(&state)
    }
    static func configureFixtureWave3To6Part1(_ state: inout CollectedState) {
        configureFixtureWave3To6Part1Segment1(&state)
        configureFixtureWave3To6Part1Segment2(&state)
    }

    static func configureFixtureWave3To6Part1Segment1(_ state: inout CollectedState) {
        configureFixtureWave3To6Part1Segment1Leaf1(&state)
        configureFixtureWave3To6Part1Segment1Leaf2(&state)
    }

    static func configureFixtureWave3To6Part1Segment1Leaf1(_ state: inout CollectedState) {



        // Wave-3: sudoers / periodic / electron / gatekeeper (GK already false in protections)
        state.collectorNotes["privesc.sudoers_signals"] = "readable:/etc/sudoers|nopasswd_hint:synthetic"
        state.collectorNotes["privesc.periodic_paths"] = "writable:/tmp/rootstock-red-periodic-synth"
        state.collectorNotes["lool.electron_devtools"] = "--inspect=9229|electron_app=SyntheticApp"
        state.codesignSamples = [
            CodesignSample(path: "/tmp/rootstock-red-synth/unsigned", signature: .init(signed: false, hardenedRuntime: false, getTaskAllow: true), notes: ["synthetic unsigned"]),
        ]
        state.runningApps = [
            RunningAppInfo(name: "Code", bundleIdentifier: "com.microsoft.VSCode", path: "/Applications/Visual Studio Code.app"),
            RunningAppInfo(name: "Slack", bundleIdentifier: "com.tinyspeck.slackmacgap", path: "/Applications/Slack.app"),
        ]

    }

    static func configureFixtureWave3To6Part1Segment1Leaf2(_ state: inout CollectedState) {
        state.esf = ESFPostureState(
            frameworkPresent: true,
            clientPaths: [],
            systemExtensionCount: 0,
            edrHints: [],
            notes: ["synthetic: ES framework present, no client path hits"]
        )
        state.patchDebt = PatchDebtState(
            osVersion: "13.6.0",
            osBuild: "22G120",
            softwareUpdatePlistPresent: false,
            lastUpdateHints: ["synthetic_lag"],
            majorVersionLag: 2,
            notes: ["synthetic multi-major lag for CVE suggester"]
        )
        }

    static func configureFixtureWave3To6Part1Segment2(_ state: inout CollectedState) {
        configureFixtureWave3To6Part1Segment2Leaf1(&state)
        configureFixtureWave3To6Part1Segment2Leaf2(&state)
    }

    static func configureFixtureWave3To6Part1Segment2Leaf1(_ state: inout CollectedState) {

        state.tcc = TCCState(
            fullDiskAccessLikely: true,
            notes: ["synthetic FDA path listability", "graph domains present"],
            probeMethod: "synthetic+graph",
            domainSignals: [
                "ScreenCapture=tool_present",
                "Accessibility=tcc_support_paths_present",
                "Automation=osascript_present",
                "CameraMic=avfoundation_present",
                "FullDiskAccess=likely",
                "FilesAndFolders=Desktop+Documents",
            ]
        )
        state.launchConstraints = LaunchConstraintState(
            constrainedPaths: [],
            unconstrainedRiskPaths: ["/tmp/debug.app/Contents/MacOS/debug"],
            notes: ["synthetic unconstrained risk without LC artifact"]
        )
        state.collectorNotes["collect.esf_endpoint_security"] = "framework=true clients=0 sysext≈0 hints=0"
        state.collectorNotes["collect.tcc_permission_graph"] =
            "ScreenCapture=tool_present;Automation=osascript_present;FullDiskAccess=likely"
        state.collectorNotes["cve.patch_debt"] = "synthetic"
        // Ensure multi-stage LOOBin chain has discover+execute+persist (+security for 4th stage)
    }

    static func configureFixtureWave3To6Part1Segment2Leaf2(_ state: inout CollectedState) {
        state.loobins = state.loobins + [
            LOOBinHit(name: "security", path: "/usr/bin/security", present: true, tactics: ["credential-access"]),
            LOOBinHit(name: "curl", path: "/usr/bin/curl", present: true, tactics: ["execution"]),
        ]
        // Multiple helpers for XPC client-validation surface
        state.privilegedHelperTools = state.privilegedHelperTools + [
            "/tmp/rootstock-red-synthetic/PrivilegedHelperTools/com.example.helper2",
            "/tmp/rootstock-red-synthetic/PrivilegedHelperTools/com.example.helper3",
        ]

            }

    static func configureFixtureWave3To6Part2(_ state: inout CollectedState) {
        configureFixtureWave3To6Part2Segment1(&state)
        configureFixtureWave3To6Part2Segment2(&state)
    }

    static func configureFixtureWave3To6Part2Segment1(_ state: inout CollectedState) {
        configureFixtureWave3To6Part2Segment1Leaf1(&state)
        configureFixtureWave3To6Part2Segment1Leaf2(&state)
    }

    static func configureFixtureWave3To6Part2Segment1Leaf1(_ state: inout CollectedState) {


        state.networkExtension = NetworkExtensionState(
            frameworkPresent: true,
            vpnConfigPaths: [],
            contentFilterHints: [],
            packetTunnelHints: [],
            neAppPaths: [],
            notes: ["synthetic: thin NE inventory, no content filter"]
        )
        state.authRights = AuthRightsState(
            authDbPresent: true,
            authDbPath: "/var/db/auth.db",
            authorizationPlistPaths: ["/System/Library/Security/authorization.plist"],
            packageKitPaths: ["/System/Library/PrivateFrameworks/PackageKit.framework"],
            rightsHintCount: 3,
            notes: ["synthetic auth.db + PackageKit surface"]
        )
    }

    static func configureFixtureWave3To6Part2Segment1Leaf2(_ state: inout CollectedState) {
        state.developerToolchain = DeveloperToolchainState(
            xcodePresent: true,
            commandLineToolsPresent: true,
            toolchainPaths: ["/Applications/Xcode.app", "/Library/Developer/CommandLineTools"],
            dualUseBinaries: [
                "/usr/bin/lldb",
                "/usr/bin/dtrace",
                "/usr/bin/codesign",
                "/usr/bin/otool",
            ],
            notes: ["synthetic Xcode/CLT dual-use inventory"]
        )
        state.timeMachine = TimeMachineState(
            preferencesPresent: true,
            backupPaths: ["/Volumes/TimeMachine/Backups.backupdb"],
            localSnapshotHints: [".localsnapshots present"],
            volumeMountHints: ["/Volumes/TimeMachine"],
            notes: ["synthetic TM prefs + snapshot hints"]
        )
        }

    static func configureFixtureWave3To6Part2Segment2(_ state: inout CollectedState) {
        state.configProfileSideload = ConfigProfileSideloadState(
            userMobileconfigPaths: [
                NSHomeDirectory() + "/Downloads/synthetic-vpn.mobileconfig",
            ],
            downloadsProfileHints: ["Downloads/*.mobileconfig"],
            profileInstallDbPresent: false,
            notes: ["synthetic user mobileconfig on unmanaged host"]
        )
        state.collectorNotes["ne.filter_gap"] = "contentFilter=0"
        state.collectorNotes["collect.network_extension"] = "contentFilter=0 filters=0"
        state.collectorNotes["collect.auth_rights"] = "authdb+packagekit"
        state.collectorNotes["collect.developer_toolchain"] = "xcode=true clt=true"
        state.collectorNotes["dev.toolchain_present"] = "1"
        state.collectorNotes["collect.time_machine"] = "tm+fda"
        state.collectorNotes["tm.snapshot_surface"] = "1"
        state.collectorNotes["collect.config_profile_sideload"] = "user_mobileconfig"
        state.collectorNotes["profile.sideload"] = "1"

            }

}
