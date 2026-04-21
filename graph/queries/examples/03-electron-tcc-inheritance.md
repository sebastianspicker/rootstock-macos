# Example Output: Electron TCC Inheritance Map

**Query:** `03-electron-tcc-inheritance.cypher`
**Data source:** Typical macOS 14 developer workstation scan

## Results

```
╒══════════════╤══════════════════════════════════╤════════════════════════════════════════════════════════════════════╤═══════════════════════════════════════════════════╤══════════════════╕
│ app_name     │ bundle_id                        │ inherited_permissions                                              │ injection_methods                                 │ permission_count │
╞══════════════╪══════════════════════════════════╪════════════════════════════════════════════════════════════════════╪═══════════════════════════════════════════════════╪══════════════════╡
│ "Slack"      │ "com.tinyspeck.slackmacgap"      │ ["Microphone", "Camera", "Screen Recording"]                      │ ["electron_env_var", "missing_library_validation"]│ 3                │
├──────────────┼──────────────────────────────────┼────────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────────┼──────────────────┤
│ "VS Code"    │ "com.microsoft.VSCode"            │ ["Accessibility", "Full Disk Access"]                             │ ["electron_env_var", "dyld_insert"]               │ 2                │
└──────────────┴──────────────────────────────────┴────────────────────────────────────────────────────────────────────┴───────────────────────────────────────────────────┴──────────────────┘
```

## Attack Technique

```bash
# Launch Slack's Electron runtime as Node.js with an attacker script:
ELECTRON_RUN_AS_NODE=1 /Applications/Slack.app/Contents/MacOS/Slack \
    /tmp/attacker.js
```

The spawned Node.js process inherits Slack's Microphone, Camera, and
Screen Recording TCC grants — enabling silent audio/video surveillance.

## Analysis

- **Slack** is the highest-risk result: 3 sensitive TCC permissions + injectable
  via electron_env_var.
- **VS Code** with FDA is particularly dangerous — Node.js child process can read
  all files on the system.
