# Platform limitations

Rootstock Blue works with evidence that macOS and the operator make available.
These limits affect what it can collect, parse, and prove:

- Encrypted FileVault media requires a valid password, recovery key, or other
  operator-provided access material.
- The project does not extract Secure Enclave secrets or full physical memory
  from Apple silicon.
- `record inject` accepts synthetic fixture events. It does not subscribe to
  Endpoint Security and cannot authorize or block activity.
- Network inspection does not include Packet Tunnel traffic or full packet
  capture.
- Offline images and copied artifacts can be incomplete, encrypted, corrupted,
  or produced by an unsupported macOS schema.
- Case checksums detect internal changes but cannot authenticate the evidence
  source. Format v0 also lacks atomic multi-file recording and power-loss
  durability guarantees.
- Apple silicon virtual machines are not assumed to be hermetic environments
  for adversarial sample analysis.
- Blue does not currently parse offline Active Directory data or Kerberos
  caches as first-class evidence. The core collector and Red assessment expose
  different host evidence for those areas.
- Core scan and Red findings imports are optional bridges. They are not
  required for the default case workflow.

See the [product family map](../../docs/FAMILY.md) and
[case package contract](case-package-v0.md). Product exclusions are maintained
separately in [non-goals](non-goals.md).
