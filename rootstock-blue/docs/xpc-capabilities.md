# XPC capabilities

Allowlisted only (`RootstockBlueXPC.XPCCapability`):

- `getAgentStatus`
- `startESProfile`
- `stopES`
- `collectPack`
- `exportCase`
- `getLossCounters`

## Forbidden (must never be added)

- `runShell`
- `disableSIP`
- `readArbitraryPath` (without collect pack)
- `bypassTCC`
- `crackFileVault`
- `installKext`
