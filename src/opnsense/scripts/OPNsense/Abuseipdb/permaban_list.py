#!/usr/bin/env python3
"""
Emit the current Perma-Block list as JSON for the GUI.

Copyright (c) 2026 Kai Schlestein
BSD 2-Clause.
"""
import sys

from _common import get_db, out_json
from permaban_count import pfctl_counters


def main() -> int:
    limit = 500
    if len(sys.argv) > 1:
        try:
            limit = max(1, min(5000, int(sys.argv[1])))
        except ValueError:
            pass

    db = get_db()
    rows = db.execute(
        "SELECT ip, added_ts, source, note, "
        "       cumulative_hits, pf_last_seen, last_hit_ts "
        "FROM permaban "
        "ORDER BY added_ts DESC LIMIT ?",
        (limit,),
    ).fetchall()
    # Live pf counters — captures hits that happened between the last cron
    # run and right now. Cheap (one in-memory kernel read) but skipped when
    # the table is empty to avoid an unnecessary pfctl invocation.
    live = pfctl_counters() if rows else {}

    data = []
    for r in rows:
        ip, added_ts, source, note, cum, pf_last, last_hit = r
        current = live.get(ip, 0)
        # Counter on disk advances when the cron sampler runs; the part
        # between samples is `current - pf_last` (or just `current` after a
        # reboot). Fold it in so the UI always shows the real total.
        if current >= pf_last:
            extra = current - pf_last
        else:
            extra = current
        data.append({
            "ip": ip,
            "added_ts": added_ts,
            "source": source or "",
            "note": note or "",
            "hits": cum + extra,
            "current_session": current,
            "last_hit_ts": last_hit,
        })
    total = db.execute("SELECT COUNT(*) FROM permaban").fetchone()[0]
    out_json({"status": "ok", "data": {"rows": data, "total": total}})
    db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
