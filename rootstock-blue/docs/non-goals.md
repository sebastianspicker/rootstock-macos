# Non-goals

Rootstock Blue does not currently provide:

- a multi-platform endpoint monitor or enterprise EDR replacement;
- a SIEM, MDM service, or Santa decision engine;
- System Integrity Protection, TCC, or Full Disk Access bypasses;
- FileVault recovery without operator-supplied access material;
- Secure Enclave secret extraction;
- full physical-memory acquisition on Apple silicon;
- full packet capture or a Packet Tunnel inspection product;
- a cloud detonation service;
- complete coverage of every mac_apt plugin or macOS artifact;
- export of Keychain secrets, private keys, session tokens, or `kcpassword`
  values.

Offline parsing, case management, detections, and reporting are the primary
alpha path. Optional integrations and live surfaces are limited to the
implemented commands and platform approvals described in the README and
[limitations](limitations.md).
