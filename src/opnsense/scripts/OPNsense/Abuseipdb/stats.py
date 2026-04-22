#!/usr/bin/env python3
"""
Return aggregated AbuseIPDB stats as JSON.

Copyright (c) 2026 Kai Schlestein
BSD 2-Clause.
"""
import os
import sys
from _common import STATE_DIR, out_json


def main() -> int:
    blocklist_file = os.path.join(STATE_DIR, "blocklist.txt")
    blocklist_count = 0
    if os.path.exists(blocklist_file):
        with open(blocklist_file, "r", encoding="ascii", errors="replace") as fh:
            blocklist_count = sum(1 for line in fh if line.strip())

    out_json({
        "blocklist_ips": blocklist_count,
        "reports_today": 0,      # phase 5
        "quota_remaining": None,  # phase 5
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
