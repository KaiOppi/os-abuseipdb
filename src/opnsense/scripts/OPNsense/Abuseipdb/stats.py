#!/usr/bin/env python3
"""
Return aggregated AbuseIPDB stats as JSON.

Copyright (c) 2026 Kai Schlestein
BSD 2-Clause.
"""
import os
import sys
import time
from _common import BLOCKLIST_FILE, STATE_DIR, get_db, out_json


def main() -> int:
    blocklist_count = 0
    blocklist_mtime = None
    if os.path.exists(BLOCKLIST_FILE):
        with open(BLOCKLIST_FILE, "r", encoding="ascii", errors="replace") as fh:
            blocklist_count = sum(1 for line in fh if line.strip())
        blocklist_mtime = int(os.path.getmtime(BLOCKLIST_FILE))

    data = {
        "blocklist_ips": blocklist_count,
        "blocklist_last_update": blocklist_mtime,
        "last_run": None,
        "last_run_ok": None,
        "quota_remaining": None,
        "reports_today": 0,
        "reports_total": 0,
    }

    if os.path.exists(os.path.join(STATE_DIR, "state.sqlite")):
        db = get_db()
        row = db.execute(
            "SELECT ts, ok, quota_remaining FROM blacklist_runs ORDER BY ts DESC LIMIT 1"
        ).fetchone()
        if row:
            data["last_run"] = row[0]
            data["last_run_ok"] = bool(row[1])
            data["quota_remaining"] = row[2]

        midnight = int(time.mktime(time.strptime(time.strftime("%Y-%m-%d 00:00:00"), "%Y-%m-%d %H:%M:%S")))
        row = db.execute(
            "SELECT COUNT(*) FROM reports WHERE ts >= ? AND ok = 1", (midnight,)
        ).fetchone()
        data["reports_today"] = row[0] if row else 0
        row = db.execute("SELECT COUNT(*) FROM reports WHERE ok = 1").fetchone()
        data["reports_total"] = row[0] if row else 0
        db.close()

    out_json(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
