import XCTest
import RootstockCore
import MacEnumKit
import MacArtifactKit
@testable import MacVulnKit

extension AttackVectorTests {
    static func configureFixtureWave7To8(_ state: inout CollectedState) {
        configureFixtureWave7To8Part1(&state)
        configureFixtureWave7To8Part2(&state)
        configureFixtureWave7To8Part3(&state)
    }
    static func configureFixtureWave7To8Part1(_ state: inout CollectedState) {
        configureFixtureWave7To8Part1Segment1(&state)
        configureFixtureWave7To8Part1Segment2(&state)
    }

    static func configureFixtureWave7To8Part1Segment1(_ state: inout CollectedState) {
        configureFixtureWave7To8Part1Segment1Leaf1(&state)
        configureFixtureWave7To8Part1Segment1Leaf2(&state)
    }

    static func configureFixtureWave7To8Part1Segment1Leaf1(_ state: inout CollectedState) {



        state.appSandboxEntitlements = AppSandboxEntitlementState(
            appSamples: [
                "/Applications/Slack.app",
                "/Applications/Visual Studio Code.app",
                "/Applications/Google Chrome.app",
            ],
            sandboxedHints: ["/System/Library/Sandbox"],
            dangerousEntitlementHints: ["tool:/usr/bin/codesign"],
            unsandboxedRiskPaths: [
                "/Applications/Slack.app",
                "/Applications/Visual Studio Code.app",
            ],
            notes: ["synthetic thick-client entitlement surface"]
        )
    }

    static func configureFixtureWave7To8Part1Segment1Leaf2(_ state: inout CollectedState) {
        state.notarizationStapling = NotarizationStaplingState(
            toolingPaths: ["/usr/bin/stapler", "/usr/sbin/spctl", "/usr/bin/codesign"],
            ticketCacheHints: ["/var/db/SystemPolicyConfiguration"],
            unstapledOrAdHocHints: [
                NSHomeDirectory() + "/Downloads/synthetic-tool.dmg",
                NSHomeDirectory() + "/Downloads/unsigned.pkg",
            ],
            assessmentToolsPresent: true,
            notes: ["synthetic notarization/stapling surface"]
        )
        state.virtualizationContainers = VirtualizationContainerState(
            containerToolPaths: ["/usr/local/bin/docker", "/Applications/Docker.app"],
            hypervisorAppPaths: ["/Applications/UTM.app"],
            frameworkPaths: ["/System/Library/Frameworks/Virtualization.framework"],
            dualUsePresent: true,
            notes: ["synthetic virt/container dual-use"]
        )
        }

    static func configureFixtureWave7To8Part1Segment2(_ state: inout CollectedState) {
        configureFixtureWave7To8Part1Segment2Leaf1(&state)
        configureFixtureWave7To8Part1Segment2Leaf2(&state)
    }

    static func configureFixtureWave7To8Part1Segment2Leaf1(_ state: inout CollectedState) {

        state.continuityAirDrop = ContinuityAirDropState(
            airdropPrefPaths: [
                NSHomeDirectory() + "/Library/Preferences/com.apple.sharingd.plist",
            ],
            continuityFrameworkPaths: [
                "/System/Library/PrivateFrameworks/Sharing.framework",
                "/usr/libexec/sharingd",
            ],
            nearbyShareHints: ["/usr/libexec/rapportd"],
            proximitySurfacePresent: true,
            notes: ["synthetic Continuity/AirDrop surface"]
        )
        state.fileVaultEscrow = FileVaultEscrowState(
            fileVaultOn: false,
            escrowPathHints: [
                "/Library/Preferences/com.apple.security.FDERecoveryKeyEscrow.plist",
            ],
            institutionalEscrowHints: ["/Library/Managed Preferences"],
            fdesetupPresent: true,
            notes: ["synthetic FV off + escrow paths - never recovery keys"]
        )
        // Align protections FV with escrow for cluster compounds
    }

    static func configureFixtureWave7To8Part1Segment2Leaf2(_ state: inout CollectedState) {
        state.protections = ProtectionsState(
            sipEnabled: false,
            gatekeeperEnabled: false,
            fileVaultOn: false,
            notes: ["synthetic: SIP/GK/FV weak for Wave-7 compounds"]
        )
        state.collectorNotes["collect.app_sandbox_entitlements"] = "apps=3 risk=2"
        state.collectorNotes["collect.notarization_stapling"] = "tools=3 delivery=2"
        state.collectorNotes["collect.virtualization_containers"] = "dualUse=true"
        state.collectorNotes["collect.continuity_airdrop"] = "surface=true"
        state.collectorNotes["collect.filevault_escrow"] = "fv=false escrow=1"

            }

    static func configureFixtureWave7To8Part2(_ state: inout CollectedState) {
        configureFixtureWave7To8Part2Segment1(&state)
        configureFixtureWave7To8Part2Segment2(&state)
        configureFixtureWave7To8Part2Segment3(&state)
    }

    static func configureFixtureWave7To8Part2Segment1(_ state: inout CollectedState) {
        configureFixtureWave7To8Part2Segment1Leaf1(&state)
        configureFixtureWave7To8Part2Segment1Leaf2(&state)
    }

    static func configureFixtureWave7To8Part2Segment1Leaf1(_ state: inout CollectedState) {


        state.clickFixTerminalDelivery = ClickFixTerminalDeliveryState(
            terminalAppPaths: ["/System/Applications/Utilities/Terminal.app", "/bin/zsh"],
            scriptEditorPaths: ["/System/Applications/Utilities/Script Editor.app", "/usr/bin/osascript"],
            loaderBinaryPaths: ["/usr/bin/curl", "/usr/bin/osascript", "/bin/zsh", "/bin/bash"],
            pasteWarningHints: [NSHomeDirectory() + "/Library/Preferences/com.apple.Terminal.plist"],
            deliverySurfacePresent: true,
            notes: ["synthetic ClickFix Terminal delivery surface - never builds lures"]
        )
        state.remoteAppleEvents = RemoteAppleEventsState(
            remoteAEPrefPaths: [
                "/Library/Preferences/com.apple.RemoteManagement.plist",
                "/System/Library/LaunchDaemons/com.apple.AEServer.plist",
            ],
            eppcFrameworkPaths: [
                "/System/Library/Frameworks/ScriptingBridge.framework",
                "/System/Library/CoreServices/RemoteManagement",
            ],
            remoteMgmtHints: ["/System/Library/LaunchDaemons/com.apple.screensharing.plist"],
            remoteAutomationSurfacePresent: true,
            notes: ["synthetic Remote Apple Events lateral surface - never enables RAE"]
        )
    }

    static func configureFixtureWave7To8Part2Segment1Leaf2(_ state: inout CollectedState) {
        state.spotlightAICache = SpotlightAICacheState(
            spotlightPaths: ["/usr/bin/mdfind", "/usr/bin/mdutil", "/.Spotlight-V100"],
            metadataFrameworkPaths: [
                "/System/Library/Frameworks/CoreSpotlight.framework",
                "/System/Library/PrivateFrameworks/Spotlight.framework",
            ],
            aiCachePathHints: [NSHomeDirectory() + "/Library/Caches"],
            dataAccessSurfacePresent: true,
            notes: ["synthetic Spotlight/AI-cache surface - never dumps index contents"]
        )
        }

    static func configureFixtureWave7To8Part2Segment2(_ state: inout CollectedState) {
        configureFixtureWave7To8Part2Segment2Leaf1(&state)
        configureFixtureWave7To8Part2Segment2Leaf2(&state)
    }

    static func configureFixtureWave7To8Part2Segment2Leaf1(_ state: inout CollectedState) {

        state.securityMgmtPlane = SecurityMgmtPlaneState(
            managementCLIPaths: ["/usr/bin/systemextensionsctl", "/bin/launchctl"],
            privilegedHelperPaths: [
                "/Library/PrivilegedHelperTools/com.example.security.helper",
            ],
            unloadAdjacentHints: ["/Library/SystemExtensions", "systemextensionsctl_present"],
            managementPlanePresent: true,
            notes: ["synthetic security mgmt-plane surface - never unloads sensors"]
        )
        state.thirdPartyTCCInheritance = ThirdPartyTCCInheritanceState(
            thickClientAppPaths: [
                "/Applications/Slack.app",
                "/Applications/Visual Studio Code.app",
            ],
            embeddedInterpreterPaths: [
                "/Applications/Slack.app/Contents/Frameworks/Electron Framework.framework",
                "/usr/bin/python3",
            ],
            electronHelperPaths: [
                "/Applications/Slack.app/Contents/Frameworks/Electron Framework.framework",
            ],
            inheritanceSurfacePresent: true,
            notes: ["synthetic TCC inheritance surface - never forges grants"]
        )
    }

    static func configureFixtureWave7To8Part2Segment2Leaf2(_ state: inout CollectedState) {
        state.sshAgentKeyPath = SSHAgentKeyPathState(
            agentSocketPaths: ["/usr/bin/ssh-agent", "/tmp/synthetic-ssh-agent.sock"],
            keyPathHits: [
                NSHomeDirectory() + "/.ssh/authorized_keys",
                NSHomeDirectory() + "/.ssh/id_ed25519",
                NSHomeDirectory() + "/.ssh/config",
            ],
            sshdSupportPaths: ["/usr/sbin/sshd", "/etc/ssh/sshd_config"],
            lateralPathSurfacePresent: true,
            notes: ["synthetic SSH agent/key path surface - never reads key material"]
        )
        state.collectorNotes["collect.clickfix_terminal_delivery"] = "terminal=2 loaders=4 surface=true"
        state.collectorNotes["collect.remote_apple_events"] = "prefs=2 eppc=2 surface=true"
        state.collectorNotes["collect.spotlight_ai_cache"] = "spotlight=3 surface=true"
        state.collectorNotes["collect.security_mgmt_plane"] = "mgmt=2 helpers=1 surface=true"
        }

    static func configureFixtureWave7To8Part2Segment3(_ state: inout CollectedState) {
        state.collectorNotes["collect.third_party_tcc_inheritance"] = "thick=2 electron=1 surface=true"
        }

    static func configureFixtureWave7To8Part3(_ state: inout CollectedState) {
        state.collectorNotes["collect.ssh_agent_key_path"] = "agent=2 keys=3 surface=true"
        }

}
