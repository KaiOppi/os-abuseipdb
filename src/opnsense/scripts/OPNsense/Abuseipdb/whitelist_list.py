#!/usr/bin/env python3
"""
Emit the operator-managed whitelist as JSON for the GUI. Includes a per-
IP skip counter pulled from whitelist_skips so the user can see which
entries are actually doing work.

Copyright (c) 2026 Kai Schlestein
BSD 2-Clause.
"""
import sys
import time

from _common import get_db, out_json


def main() -> int:
    limit = 500
    if len(sys.argv) > 1:
        try:
            limit = max(1, min(5000, int(sys.argv[1])))
        except ValueError:
            pass

    db = get_db()
    rows = db.execute(
        "SELECT ip, added_ts, source, note FROM whitelist "
        "ORDER BY added_ts DESC LIMIT ?",
        (limit,),
    ).fetchall()

    # Per-IP skip counter (last 30 days; older entries are pruned by
    # record_whitelist_skip itself). Cheap aggregation — n is small.
    skip_counts = {}
    cutoff = int(time.time()) - 30 * 86400
    for ip, n in db.execute(
        "SELECT ip, COUNT(*) FROM whitelist_skips WHERE ts >= ? GROUP BY ip",
        (cutoff,),
    ).fetchall():
        skip_counts[ip] = n

    data = [
        {
            "ip": r[0],
            "added_ts": r[1],
            "source": r[2] or "",
            "note": r[3] or "",
            "skips_30d": skip_counts.get(r[0], 0),
        }
        for r in rows
    ]
    total = db.execute("SELECT COUNT(*) FROM whitelist").fetchone()[0]
    skips_total = db.execute(
        "SELECT COUNT(*) FROM whitelist_skips WHERE ts >= ?",
        (cutoff,),
    ).fetchone()[0]

    out_json({"status": "ok", "data": {
        "rows": data,
        "total": total,
        "skips_30d_total": skips_total,
    }})
    db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
