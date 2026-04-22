#!/usr/bin/env python3
"""
Return recent AbuseIPDB reports (from local SQLite) as JSON.

Copyright (c) 2026 Kai Schlestein
BSD 2-Clause.

Args: optional limit N (default 100, max 500).
"""
import os
import sys
from _common import STATE_DIR, get_db, out_json


def main() -> int:
    limit = 100
    if len(sys.argv) > 1:
        try:
            limit = max(1, min(500, int(sys.argv[1])))
        except ValueError:
            pass

    rows = []
    if os.path.exists(os.path.join(STATE_DIR, "state.sqlite")):
        db = get_db()
        for r in db.execute(
            "SELECT ts, ip, categories, ok, message FROM reports ORDER BY ts DESC LIMIT ?",
            (limit,),
        ):
            rows.append({
                "ts": r[0],
                "ip": r[1],
                "categories": r[2],
                "ok": bool(r[3]),
                "message": r[4] or "",
            })
        db.close()

    out_json({"rows": rows, "total": len(rows)})
    return 0


if __name__ == "__main__":
    sys.exit(main())
