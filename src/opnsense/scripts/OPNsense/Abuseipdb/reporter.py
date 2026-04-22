#!/usr/bin/env python3
"""
Phase-1 stub — reporter will be implemented in phase 5.

Copyright (c) 2026 Kai Voss / IT-Service NF
BSD 2-Clause.
"""
import sys
from _common import get_config


def main() -> int:
    cfg = get_config()
    if cfg["reporter"]["enabled"] != "1":
        print("Reporter disabled.")
        return 0
    print("Reporter stub — real implementation follows in phase 5.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
