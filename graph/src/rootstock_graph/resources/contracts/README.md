# Packaged contract mirrors

This directory contains read-only copies of contracts needed by the installed
graph package. The canonical contracts live in the repository's
[contracts directory](../../../../../contracts/README.md).

Do not edit these copies directly. Update the canonical contract and then copy
it here. `scripts/check-contracts.py` requires the Family version 1 schema to
remain byte-for-byte identical in both locations.
