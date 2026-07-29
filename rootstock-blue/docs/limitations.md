# Platform limitations

- Encrypted FileVault media requires a valid password, recovery key, or other
  operator-provided access material.
- The project does not extract Secure Enclave secrets or full physical memory
  from Apple silicon.
- Live Endpoint Security operation requires restricted entitlements, Full Disk
  Access, root or system extension approval as applicable, and separate
  deployment validation. Concurrent Endpoint Security client capacity is
  finite.
- The current Endpoint Security implementation is mock-backed for the default
  alpha test path. AUTH or blocking behavior is not enabled by default.
- Endpoint Security does not provide packet content. Rootstock Blue does not
  implement Packet Tunnel inspection or full packet capture.
- Offline images and copied artifacts can be incomplete, encrypted, corrupted,
  or produced by an unsupported macOS schema.
- Apple silicon virtual machines are not assumed to be hermetic environments
  for adversarial sample analysis.
- First-class offline Active Directory and Kerberos cache parsing is not part
  of the current Blue scope. The Core and Red packages expose different host
  evidence for those areas.
- Core scan and Red findings imports are optional bridges. They are not
  required for the default case workflow.

See the [product family map](../../docs/FAMILY.md) and
[case package contract](case-package-v0.md).
