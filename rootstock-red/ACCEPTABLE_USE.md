# Acceptable use policy

Rootstock Red is intended for security assessment and technique validation on
systems the operator owns or has explicit written authorization to test.

## Intended use

- Authorized security assessments
- Purple-team and detection-engineering exercises in controlled environments
- Defensive posture review
- Academic or professional training with consenting participants
- Reversible Red Lab validation covered by written rules of engagement

## Unacceptable use

- Unauthorized access, surveillance, credential theft, or data exfiltration
- Deployment as malware, ransomware, a commodity remote-access tool, or a
  production implant
- Attempts to evade notarization, endpoint controls, or detection outside an
  authorized engagement
- Red Lab execution without an identified operator, scope, and target owner

## Operational controls

- The default `rootstock-red` executable is read-only assessment software.
- `rootstock-red-lab` is a separate executable with authorization checks and
  dry-run defaults.
- `~/.rootstock-red/DISABLE` acts as a local kill switch.
- BTM and other proprietary stores are reported only to the depth implemented
  and tested. The project does not claim a full binary decoder where none
  exists.
- Path-to-impact vectors are assessment findings, not exploit delivery.

Operators remain responsible for applicable law, organizational policy, and
engagement authorization.

This policy states project expectations. It does not replace, restrict, or add
terms to the Apache-2.0 license. See [SECURITY.md](SECURITY.md) and
[NOT_FOR_PRODUCTION_IMPLANT.md](NOT_FOR_PRODUCTION_IMPLANT.md).
