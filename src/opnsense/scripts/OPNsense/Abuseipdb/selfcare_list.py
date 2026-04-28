#!/usr/bin/env python3
"""
Emit the current self-defense block list as JSON for the GUI.

Copyright (c) 2026 Kai Schlestein
BSD 2-Clause.
"""
import sys
import time

from _common import get_db, out_json


def main() -> int:
    limit = 200
    if len(sys.argv) > 1:
        try:
            limit = max(1, min(1000, int(sys.argv[1])))
        except ValueError:
            pass

    db = get_db()
    now = int(time.time())
    rows = db.execute(
        "SELECT ip, added_ts, expires_ts, source, categories, iface "
        "FROM selfcare_entries "
        "WHERE removed_ts IS NULL AND expires_ts > ? "
        "ORDER BY added_ts DESC LIMIT ?",
        (now, limit),
    ).fetchall()
    data = [
        {
            "ip": r[0],
            "added_ts": r[1],
            "expires_ts": r[2],
            "remaining_sec": max(0, r[2] - now),
            "source": r[3] or "",
            "categories": r[4] or "",
            "iface": r[5] or "",
        }
        for r in rows
    ]

    count_total = db.execute(
        "SELECT COUNT(*) FROM selfcare_entries WHERE removed_ts IS NULL AND expires_ts > ?",
        (now,),
    ).fetchone()[0]

    out_json({"status": "ok", "data": {"rows": data, "total_active": count_total}})
    db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
