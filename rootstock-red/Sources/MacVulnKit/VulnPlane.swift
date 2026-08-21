import Foundation
import RootstockCore

/// Vulnerability assessment planes (not network exploit scanning).
public enum VulnPlane: String, Codable, Sendable, CaseIterable {
    case cvePatchDebt = "A_cve"
    case misconfiguration = "B_misconfig"
    case tccExposure = "C_tcc"
    case codeIdentity = "D_codesign_dylib"
    case mdmPosture = "E_mdm"
    case sandboxEntitlements = "F_sandbox"
    case xpcSurface = "G_xpc"
    case persistenceExposure = "H_persist"
    case authPosture = "I_auth"
    case localNetwork = "J_network"
}

/// Shared posture signals used by remote-compound vectors.
///
/// These vectors are assessment-only: the signals rank observed local surfaces and never
/// enable a service, access protected data, or simulate a remote session.
struct RemoteCompoundSignals: Sendable {
    let remote: Bool
    let fullDiskAccess: Bool
    let sensorThin: Bool

    init(state: CollectedState) {
        remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        fullDiskAccess = state.tcc?.fullDiskAccessLikely == true
        sensorThin = state.esf?.clientPaths.isEmpty == true || state.securityProducts.filter(\.present).isEmpty
    }

    var hasAmplifier: Bool {
        remote || fullDiskAccess || sensorThin
    }

    var severity: Severity {
        if remote && fullDiskAccess {
            return .high
        }
        return hasAmplifier ? .medium : .low
    }

    func surfaceSeverity(pathPairCount: Int) -> Severity {
        if remote && fullDiskAccess && pathPairCount >= 3 {
            return .high
        }
        if remote || fullDiskAccess || pathPairCount >= 2 {
            return .medium
        }
        return .low
    }
}

struct PlaneSignal: Sendable {
    let name: String
    let isPresent: Bool
}

func presentPlaneNames(_ signals: [PlaneSignal]) -> [String] {
    signals.compactMap { $0.isPresent ? $0.name : nil }
}

func clusterAmplifierLabels(state: CollectedState) -> [String] {
    var labels: [String] = []
    if state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true { labels.append("remote") }
    if state.tcc?.fullDiskAccessLikely == true { labels.append("fda") }
    if state.protections?.sipEnabled == false { labels.append("sip_off") }
    if state.protections?.gatekeeperEnabled == false { labels.append("gk_off") }
    if let esf = state.esf, esf.clientPaths.isEmpty { labels.append("sensor_gap") }
    if state.securityProducts.filter(\.present).isEmpty { labels.append("products_absent") }
    return labels
}

func hasPlaneSurface<T>(
    _ surface: T?,
    isPresent: (T) -> Bool?,
    primaryCount: (T) -> Int,
    secondaryCount: (T) -> Int
) -> Bool {
    guard let surface else { return false }
    return isPresent(surface) == true || primaryCount(surface) > 0 || secondaryCount(surface) > 0
}

enum VectorEvidence {
    static func paths(_ paths: [String], type: String, detail: String, limit: Int) -> [Evidence] {
        paths.prefix(limit).map { path in
            Evidence(type: type, path: path, detail: detail)
        }
    }

    static func notes(_ notes: [String], type: String, limit: Int) -> [Evidence] {
        notes.prefix(limit).map { note in
            Evidence(type: type, detail: note)
        }
    }
}
