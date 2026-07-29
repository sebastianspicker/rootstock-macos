# ES subscription profiles

Monitor-only by default. Auth mode is not implemented.

| Profile | Use | Events (summary) |
|---------|-----|------------------|
| `ir` | Live IR triage | exec/fork/exit, auth/ssh/sudo, BTM, XProtect, limited file, TCC_MODIFY |
| `research` | Detonation / purple team | Broader file + XPC + remote thread + CS invalidated |
| `quiet` | Low noise | exec/exit, BTM add, XProtect |

JSON mirrors: `Config/Profiles/*.json`  
Swift builtins: `ESSubscriptionProfile.builtin(_:)`

Real live client requires Apple ES entitlement + FDA + system extension approval.
