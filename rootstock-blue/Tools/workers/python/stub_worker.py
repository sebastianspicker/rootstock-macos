#!/usr/bin/env python3
"""Out-of-process worker stub. Not linked into RootstockBlueES."""
import json
import sys


def main() -> int:
    print(json.dumps({"status": "stub", "message": "no work performed"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
