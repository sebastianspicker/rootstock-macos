import Foundation
import RootstockCore

/// Presence checks for common security tools (paths / bundles only - no process storm).
public struct SecurityProductsCollector: Collector {
    public static let id = "collect.security_products"
    public static let cost: CollectorCost = .low

    /// (vendor/product name, absolute path). Multiple paths per product are intentional.
    private static let catalog: [(String, String)] = [
        // CrowdStrike
        ("CrowdStrike Falcon", "/Library/CS/falconctl"),
        ("CrowdStrike Falcon", "/Applications/Falcon.app"),
        ("CrowdStrike Falcon", "/Library/SystemExtensions/com.crowdstrike.falcon.Agent.systemextension"),
        ("CrowdStrike Falcon", "/Library/LaunchDaemons/com.crowdstrike.falcond.plist"),

        // SentinelOne
        ("SentinelOne", "/Library/Sentinel/sentinel-agent.bundle"),
        ("SentinelOne", "/Applications/SentinelOne"),
        ("SentinelOne", "/Library/LaunchDaemons/com.sentinelone.sentineld.plist"),
        ("SentinelOne", "/usr/local/bin/sentinelctl"),

        // Microsoft Defender
        ("Microsoft Defender", "/Applications/Microsoft Defender.app"),
        ("Microsoft Defender", "/Library/Preferences/com.microsoft.wdav.plist"),
        ("Microsoft Defender", "/Library/LaunchDaemons/com.microsoft.wdav.launchdaemon.plist"),
        ("Microsoft Defender", "/usr/local/bin/mdatp"),

        // Jamf
        ("Jamf Protect", "/Library/Application Support/JamfProtect"),
        ("Jamf Protect", "/Applications/JamfProtect.app"),
        ("Jamf Protect", "/Library/LaunchDaemons/com.jamf.protect.daemon.plist"),
        ("Jamf", "/usr/local/bin/jamf"),
        ("Jamf", "/Library/Application Support/JAMF"),
        ("Jamf", "/usr/local/jamf/bin/jamf"),

        // Carbon Black / VMware / Broadcom
        ("Carbon Black", "/Applications/VMware Carbon Black Cloud.app"),
        ("Carbon Black", "/Applications/Carbon Black Cloud.app"),
        ("Carbon Black", "/Library/Application Support/com.vmware.carbonblack"),
        ("Carbon Black", "/Library/LaunchDaemons/com.vmware.carbonblack.daemon.plist"),
        ("Carbon Black", "/Applications/Confer.app"),

        // Elastic
        ("Elastic Endpoint", "/Library/Elastic/Endpoint"),
        ("Elastic Endpoint", "/Library/LaunchDaemons/co.elastic.endpoint.plist"),
        ("Elastic Agent", "/Library/Elastic/Agent"),
        ("Elastic Agent", "/opt/Elastic/Agent"),

        // osquery
        ("osquery", "/usr/local/bin/osqueryd"),
        ("osquery", "/opt/osquery/bin/osqueryd"),
        ("osquery", "/usr/local/bin/osqueryi"),
        ("osquery", "/Library/LaunchDaemons/io.osquery.agent.plist"),
        ("osquery", "/opt/homebrew/bin/osqueryd"),

        // Santa (Google)
        ("Santa", "/Applications/Santa.app"),
        ("Santa", "/usr/local/bin/santactl"),
        ("Santa", "/Library/LaunchDaemons/com.google.santa.daemon.plist"),
        ("Santa", "/Library/LaunchDaemons/com.northpolesec.santa.daemon.plist"),

        // Objective-See / host firewalls & monitors
        ("LuLu", "/Applications/LuLu.app"),
        ("LuLu", "/Library/LaunchDaemons/com.objective-see.lulu.plist"),
        ("KnockKnock", "/Applications/KnockKnock.app"),
        ("BlockBlock", "/Applications/BlockBlock Helper.app"),
        ("Objective-See BlockBlock", "/Applications/BlockBlock.app"),
        ("Objective-See Oversight", "/Applications/OverSight.app"),
        ("Objective-See RansomWhere", "/Applications/RansomWhere.app"),
        ("Objective-See Netiquette", "/Applications/Netiquette.app"),
        ("Objective-See ProcessMonitor", "/Applications/ProcessMonitor.app"),
        ("Objective-See FileMonitor", "/Applications/FileMonitor.app"),

        // Little Snitch / Micro Snitch
        ("Little Snitch", "/Applications/Little Snitch.app"),
        ("Little Snitch", "/Library/LaunchDaemons/at.obdev.littlesnitchd.plist"),
        ("Little Snitch", "/Library/Little Snitch"),
        ("Micro Snitch", "/Applications/Micro Snitch.app"),

        // Malwarebytes
        ("Malwarebytes", "/Applications/Malwarebytes.app"),
        ("Malwarebytes", "/Library/Application Support/Malwarebytes"),
        ("Malwarebytes", "/Library/LaunchDaemons/com.malwarebytes.mbam.frontend.agent.plist"),

        // Sophos
        ("Sophos", "/Applications/Sophos"),
        ("Sophos", "/Applications/Sophos Endpoint.app"),
        ("Sophos", "/Library/Sophos Anti-Virus"),
        ("Sophos", "/Library/LaunchDaemons/com.sophos.common.servicemanager.plist"),

        // Trend Micro
        ("Trend Micro", "/Applications/TrendMicro Security.app"),
        ("Trend Micro", "/Applications/Trend Micro Security.app"),
        ("Trend Micro", "/Library/Application Support/TrendMicro"),
        ("Trend Micro", "/Library/LaunchDaemons/com.trendmicro.icore.av.plist"),

        // Palo Alto / GlobalProtect / Cortex
        ("Palo Alto Cortex XDR", "/Applications/Cortex XDR.app"),
        ("Palo Alto Cortex XDR", "/Library/Application Support/PaloAltoNetworks/Traps"),
        ("Palo Alto Cortex XDR", "/Library/LaunchDaemons/com.paloaltonetworks.trapsd.plist"),
        ("GlobalProtect", "/Applications/GlobalProtect.app"),
        ("GlobalProtect", "/Library/LaunchAgents/com.paloaltonetworks.gp.pangpa.plist"),
        ("GlobalProtect", "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"),

        // Cisco
        ("Cisco Secure Endpoint", "/Applications/Cisco Secure Client.app"),
        ("Cisco Secure Endpoint", "/Applications/Cisco/Cisco Secure Endpoint"),
        ("Cisco Secure Endpoint", "/opt/cisco/amp"),
        ("Cisco Secure Endpoint", "/Library/LaunchDaemons/com.cisco.amp.daemon.plist"),
        ("Cisco AMP", "/Applications/Cisco AMP for Endpoints Connector.app"),
        ("Cisco Umbrella", "/Applications/Cisco Umbrella.app"),
        ("Cisco AnyConnect", "/Applications/Cisco/Cisco AnyConnect Secure Mobility Client.app"),
        ("Cisco Secure Client", "/opt/cisco/secureclient"),

        // FireEye / Trellix / Mandiant
        ("Trellix", "/Applications/Trellix"),
        ("Trellix", "/Library/FireEye"),
        ("FireEye", "/Library/FireEye"),

        // Bitdefender
        ("Bitdefender", "/Applications/Bitdefender"),
        ("Bitdefender", "/Library/Bitdefender"),

        // ESET
        ("ESET", "/Applications/ESET Endpoint Security.app"),
        ("ESET", "/Applications/ESET Endpoint Antivirus.app"),
        ("ESET", "/Library/Application Support/ESET"),

        // Avast / AVG
        ("Avast", "/Applications/Avast.app"),
        ("AVG", "/Applications/AVGAntivirus.app"),

        // Norton
        ("Norton", "/Applications/Norton.app"),
        ("Norton", "/Applications/Norton Security.app"),

        // Webroot
        ("Webroot", "/Applications/Webroot SecureAnywhere.app"),

        // Tanium
        ("Tanium", "/Library/Tanium/TaniumClient"),
        ("Tanium", "/Library/LaunchDaemons/com.tanium.taniumclient.plist"),

        // Kolide
        ("Kolide", "/usr/local/kolide-k2"),
        ("Kolide", "/Library/LaunchDaemons/com.kolide.launcher.plist"),

        // Fleet / Orbit
        ("Fleet Desktop", "/Applications/Fleet Desktop.app"),
        ("Orbit", "/opt/orbit"),
        ("Orbit", "/Library/LaunchDaemons/io.fleet.orbit.plist"),

        // Kandji
        ("Kandji", "/Library/Kandji"),
        ("Kandji", "/Library/LaunchDaemons/io.kandji.KandjiAgent.plist"),
        ("Kandji", "/Applications/Kandji Self Service.app"),

        // Mosyle
        ("Mosyle", "/Applications/Self-Service.app"),
        ("Mosyle", "/Library/Application Support/Mosyle"),

        // Intune / Company Portal
        ("Company Portal", "/Applications/Company Portal.app"),
        ("Microsoft Intune", "/Library/Intune"),

        // Google / BeyondCorp-ish
        ("Google Santa", "/Applications/Santa.app"),

        // Open-source / lab tools often present on research hosts
        ("Wireshark", "/Applications/Wireshark.app"),
        ("Burp Suite", "/Applications/Burp Suite Community Edition.app"),
        ("Burp Suite", "/Applications/Burp Suite Professional.app"),

        // Apple XProtect / MRT (always-ish present; still useful inventory)
        ("Apple XProtect", "/Library/Apple/System/Library/CoreServices/XProtect.bundle"),
        ("Apple MRT", "/Library/Apple/System/Library/CoreServices/MRT.app"),
        ("Apple Gatekeeper", "/usr/sbin/spctl"),
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var hits: [SecurityProductHit] = []
        var seen = Set<String>()
        for (name, path) in Self.catalog {
            let key = "\(name)|\(path)"
            guard !seen.contains(key) else { continue }
            seen.insert(key)
            if fm.fileExists(atPath: path) {
                hits.append(SecurityProductHit(name: name, path: path, present: true))
            }
        }
        var state = CollectedState()
        state.securityProducts = hits
        state.collectorNotes[Self.id] =
            "path presence only (\(hits.count) hits; catalog=\(Self.catalog.count))"
        return state
    }
}
