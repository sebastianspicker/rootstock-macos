import CodeSigning
import Entitlements
import Foundation
import Models
import Quarantine
import Sandbox

extension ScanOrchestrator {
    func collectApplications(config: ModuleConfig) async -> ApplicationCollection {
        let entitlementCollection = await collectEntitlementApplications(config: config)
        let codeSigningCollection = await collectCodeSigningApplications(
            config: config,
            applications: entitlementCollection.applications
        )
        let applications = await collectApplicationEnrichments(
            config: config,
            applications: codeSigningCollection.applications
        )
        return ApplicationCollection(
            applications: applications,
            errors: entitlementCollection.errors + codeSigningCollection.errors
        )
    }

    private func collectEntitlementApplications(config: ModuleConfig) async -> ApplicationCollection {
        guard config.includes(.entitlements) else {
            return ApplicationCollection(applications: [], errors: [])
        }
        let (result, elapsed) = await timed { await EntitlementDataSource().collect() }
        let applications = result.nodes.compactMap { $0 as? Application }
        if verbose {
            err("  [Entitlements] completed in \(format(elapsed))  (\(applications.count) apps)")
        }
        return ApplicationCollection(applications: applications, errors: result.errors)
    }

    private func collectCodeSigningApplications(
        config: ModuleConfig,
        applications: [Application]
    ) async -> ApplicationCollection {
        guard config.includes(.codeSigning) else {
            return ApplicationCollection(applications: applications, errors: [])
        }
        let ((enrichedApplications, errors), elapsed) = await timed {
            CodeSigningDataSource().enriched(applications: applications)
        }
        if verbose {
            err("  [CodeSigning]  completed in \(format(elapsed))  (\(enrichedApplications.count) apps)")
        }
        return ApplicationCollection(applications: enrichedApplications, errors: errors)
    }

    private func collectApplicationEnrichments(
        config: ModuleConfig,
        applications: [Application]
    ) async -> [Application] {
        guard config.includes(.entitlements),
              config.includes(.sandbox) || config.includes(.quarantine) else {
            return applications
        }
        if config.includes(.sandbox) && config.includes(.quarantine) {
            return await collectSandboxAndQuarantine(applications)
        }
        let enrichStart = Date()
        if config.includes(.sandbox) {
            let (sandboxApps, sandboxCount) = SandboxDataSource().enriched(applications: applications)
            let elapsed = Date().timeIntervalSince(enrichStart)
            if verbose { err("  [Sandbox]      completed in \(format(elapsed))  (\(sandboxCount) profiles)") }
            return sandboxApps
        }
        let (quarantineApps, quarantineCount) = QuarantineDataSource().enriched(applications: applications)
        let elapsed = Date().timeIntervalSince(enrichStart)
        if verbose { err("  [Quarantine]   completed in \(format(elapsed))  (\(quarantineCount) quarantined)") }
        return quarantineApps
    }

    private func collectSandboxAndQuarantine(_ applications: [Application]) async -> [Application] {
        let enrichStart = Date()
        async let sandboxResult = { SandboxDataSource().enriched(applications: applications) }()
        async let quarantineResult = { QuarantineDataSource().enriched(applications: applications) }()
        let ((sandboxApps, sandboxCount), (quarantineApps, quarantineCount)) = await (sandboxResult, quarantineResult)
        if verbose {
            let elapsed = Date().timeIntervalSince(enrichStart)
            err("  [Sandbox]      completed in \(format(elapsed))  (\(sandboxCount) profiles)")
            err("  [Quarantine]   completed in \(format(elapsed))  (\(quarantineCount) quarantined)")
        }
        return Self.mergeApplicationEnrichments(
            sandboxApplications: sandboxApps,
            quarantineApplications: quarantineApps
        )
    }
}
