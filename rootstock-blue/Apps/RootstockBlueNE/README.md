# RootstockBlueNE

This source-only target is outside the default SwiftPM build and test lane.
The current release does not provide a deployable Network Extension or
process-to-network correlation.

The intended boundary is a Network Extension content filter that records
process-attributed egress metadata without packet contents.

## Non-goals

- Not a Packet Tunnel or VPN (Apple TN3120)
- No full PCAP by default
- Not required for the offline case and forensics workflow
