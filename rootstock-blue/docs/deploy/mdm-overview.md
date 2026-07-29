# Live deployment prerequisites

Rootstock Blue does not provide a supported MDM deployment package in this
alpha. The app, helper, daemon, Endpoint Security, and Network Extension
directories contain source-only targets and require separate signing, entitlement,
approval, and deployment validation.

Any deployment design must account for platform controls such as:

1. System Extension allowlist payload  
2. Full Disk Access PPPC (user-approved MDM)  
3. Optional Network Extension or content-filter approval  
4. LaunchDaemon / SMAppService install for `rootstock-blued`

No payload examples in this directory are validated for deployment. Use the
chosen MDM vendor's current documentation and test on a non-production fleet.
