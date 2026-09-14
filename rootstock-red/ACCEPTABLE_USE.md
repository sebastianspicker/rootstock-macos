# Acceptable use policy

Rootstock Red is for security assessment and controlled technique validation.
Use it only on systems you own or have explicit written permission to test.

## Intended use

- Authorized security assessments
- Purple-team exercises and detection engineering in controlled environments
- Defensive posture review
- Academic or professional training with consenting participants
- Reversible Red Lab validation covered by written rules of engagement

## Unacceptable use

- Unauthorized access, surveillance, credential theft, or data exfiltration
- Deployment as malware, ransomware, a commodity remote-access tool, or a
  production implant
- Evasion of notarization, endpoint controls, or detection outside an
  authorized engagement
- Red Lab execution without an identified operator, scope, and target owner

## Operational controls

- The default `rootstock-red` executable is read-only assessment software.
- `rootstock-red-lab` is a separate executable. It asks the operator to identify
  themselves and the engagement, and it starts in dry-run mode. Those inputs do
  not prove that the operator has permission to act.
- `~/.rootstock-red/DISABLE` acts as a same-user local kill switch.
- BTM and other proprietary stores are reported only to the depth implemented
  and tested. The project does not claim a full binary decoder where none
  exists.
- Technique-oriented vector checks report possible paths to impact. They do not
  deliver exploits.

Operators are responsible for following applicable law, organizational policy,
and the written scope of the engagement.

This policy states project expectations. It does not replace, restrict, or add
terms to the Apache-2.0 license. See [SECURITY.md](SECURITY.md) and
[NOT_FOR_PRODUCTION_IMPLANT.md](NOT_FOR_PRODUCTION_IMPLANT.md).
