# macOS Security Model — LLM Reference

> Condensed reference material optimized for LLM context windows.
> Use this when Claude needs quick orientation on macOS security concepts.

## Security Layers (outer to inner)

1. **Gatekeeper** — Verifies code signing and notarization before first launch
2. **XProtect** — Signature-based malware detection (YARA rules)
3. **App Sandbox** — Per-app filesystem and resource restrictions
4. **TCC** — Per-app permission grants for sensitive resources (camera, mic, FDA)
5. **SIP** — Protects system files even from root (`/System`, `/usr`, kernel extensions)
6. **Secure Boot / T2/M-series** — Hardware root of trust, boot chain verification

## Key Terminology

- **FDA** = Full Disk Access (TCC service `kTCCServiceSystemPolicyAllFiles`)
- **SIP** = System Integrity Protection (`csrutil status` to check)
- **TCC** = Transparency, Consent, and Control (privacy permission framework)
- **Hardened Runtime** = App opts into stricter security (required for notarization)
- **Library Validation** = App only loads libraries signed by same team or Apple
- **Entitlement** = Key-value capability declared in code signature
- **Notarization** = Apple's automated malware scan for distributed apps
- **SSV** = Signed System Volume (cryptographic seal on system partition, macOS 11+)
- **ESF** = Endpoint Security Framework (kernel-level event monitoring API)
- **XPC** = Cross-Process Communication (macOS IPC mechanism via Mach ports)
- **Keychain** = macOS credential management system (login, system, iCloud keychains)
- **LKDC** = Local Key Distribution Center (Kerberos KDC on every macOS since 10.5)

## File Paths That Matter

```
~/Library/Application Support/com.apple.TCC/TCC.db        # User TCC database
/Library/Application Support/com.apple.TCC/TCC.db         # System TCC database
~/Library/Keychains/login.keychain-db                      # User login keychain
/Library/Keychains/System.keychain                         # System keychain
/System/Library/LaunchDaemons/                             # System launch daemons
/Library/LaunchDaemons/                                    # Third-party launch daemons
~/Library/LaunchAgents/                                    # User launch agents
/Library/LaunchAgents/                                     # System-wide launch agents
/var/db/dslocal/nodes/Default/                             # Local user/group directory
/etc/krb5.conf                                             # Kerberos configuration (AD)
```

## Useful Built-in Commands

```bash
# TCC
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "SELECT * FROM access"
tccutil reset All                          # Reset all TCC grants (caution!)

# Code signing
codesign -d --entitlements :- /path/to.app  # Dump entitlements
codesign -dv --verbose=4 /path/to.app       # Detailed signing info
spctl --assess /path/to.app                 # Gatekeeper assessment

# System info
csrutil status                              # SIP status
profiles show -all                          # MDM profiles
launchctl list                              # Running launch services
security list-keychains                     # List keychains
security dump-keychain -a -d                # Dump keychain (prompts!)
```
