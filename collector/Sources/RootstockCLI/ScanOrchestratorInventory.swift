import Foundation
import Models
import NetworkListeners

extension ScanOrchestrator {
    /// Assembles the inventory collections: network listeners run after application
    /// discovery (they resolve bundle IDs from it); the others are independent modules.
    func collectInventory(
        config: ModuleConfig,
        applications: [Application],
        taskResults: ModuleTaskResults,
        errors: inout [CollectionError]
    ) async -> ScanResult.InventoryCollections {
        ScanResult.InventoryCollections(
            networkListeners: await collectNetworkListeners(config: config, applications: applications, errors: &errors),
            certificateTrustSettings: collectNodes(
                taskResults.result(for: .trustSettings),
                as: TrustedCertificate.self,
                label: "TrustSettings",
                noun: "certificates",
                errors: &errors
            ),
            browserExtensions: collectNodes(
                taskResults.result(for: .browserExtensions),
                as: BrowserExtension.self,
                label: "BrowserExt",
                noun: "extensions",
                errors: &errors
            ),
            installedPackages: collectNodes(
                taskResults.result(for: .installedPackages),
                as: InstalledPackage.self,
                label: "Packages",
                noun: "receipts",
                errors: &errors
            )
        )
    }

    private func collectNetworkListeners(
        config: ModuleConfig,
        applications: [Application],
        errors: inout [CollectionError]
    ) async -> [NetworkListener] {
        guard config.includes(.networkListeners) else { return [] }
        let timedResult = await timed {
            await NetworkListenersDataSource(knownApps: applications).collect()
        }
        return collectNodes(timedResult, as: NetworkListener.self, label: "Listeners", noun: "sockets", errors: &errors)
    }
}
