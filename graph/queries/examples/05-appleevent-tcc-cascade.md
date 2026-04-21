# Example Output: Apple Event TCC Cascade

**Query:** `05-appleevent-tcc-cascade.cypher`
**Data source:** Typical macOS 14 developer workstation scan

## Results

```
╒══════════════╤══════════════════════════════╤═════════════════════╤════════════════════════════╤═════════════════════════════╤════════════════════╤═══════════════════════════╕
│ source_app   │ source_bundle_id             │ target_app          │ permission_gained           │ permission_service          │ source_is_injectable│ source_injection_methods  │
╞══════════════╪══════════════════════════════╪═════════════════════╪════════════════════════════╪═════════════════════════════╪════════════════════╪═══════════════════════════╡
│ "Script Ed." │ "com.apple.ScriptEditor"     │ "Finder"            │ "Full Disk Access"         │ "kTCCServiceSystemPolicAll" │ false              │ []                        │
├──────────────┼──────────────────────────────┼─────────────────────┼────────────────────────────┼─────────────────────────────┼────────────────────┼───────────────────────────┤
│ "Script Ed." │ "com.apple.ScriptEditor"     │ "iTerm2"            │ "Accessibility"            │ "kTCCServiceAccessibility"  │ false              │ []                        │
└──────────────┴──────────────────────────────┴─────────────────────┴────────────────────────────┴─────────────────────────────┴────────────────────┴───────────────────────────┘
```

## Analysis

Script Editor has Automation TCC grant → can send Apple Events to Finder (FDA) and iTerm2 (Accessibility).

This enables:
1. Script Editor → `tell application "Finder" to ...` — invoke Finder's file operations with FDA
2. Script Editor → `tell application "iTerm2" to ...` — drive iTerm2's Accessibility-enabled actions

Script Editor itself is not injectable (hardened runtime), reducing direct risk.
But if an attacker finds an injectable app that can invoke Script Editor or run AppleScripts,
the cascade becomes exploitable.
