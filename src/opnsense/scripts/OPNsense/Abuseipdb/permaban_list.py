#!/usr/bin/env python3
"""
Emit the current Perma-Block list as JSON for the GUI.

Copyright (c) 2026 Kai Schlestein
BSD 2-Clause.
"""
import sys

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
        "SELECT ip, added_ts, source, note FROM permaban "
        "ORDER BY added_ts DESC LIMIT ?",
        (limit,),
    ).fetchall()
    data = [
        {
            "ip": r[0],
            "added_ts": r[1],
            "source": r[2] or "",
            "note": r[3] or "",
        }
        for r in rows
    ]
    total = db.execute("SELECT COUNT(*) FROM permaban").fetchone()[0]
    out_json({"status": "ok", "data": {"rows": data, "total": total}})
    db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
