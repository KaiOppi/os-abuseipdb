#!/usr/bin/env python3
"""
Return aggregated AbuseIPDB stats as JSON.

Copyright (c) 2026 Kai Schlestein
BSD 2-Clause.
"""
import os
import sys
import time
from collections import Counter
from _common import (BLOCKLIST_FILE, STATE_DIR, get_db, get_iface_descr_map,
                     out_json)


def _split_ifaces(s: str | None) -> list[str]:
    if not s:
        return []
    return [p.strip() for p in s.split(",") if p.strip()]


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
        "selfcare_active": 0,
        "selfcare_total": 0,
        "permaban_count": 0,
        "iface_descr": {},          # identifier → friendly name (for UI)
        "by_iface": {               # all keyed by identifier (wan, opt1, ...)
            "selfcare_active": {},
            "selfcare_total": {},
            "reports_today": {},
            "reports_total": {},
        },
        "daily": {                  # last 14 days, oldest → newest
            "reports": [],
            "selfcare_added": [],
        },
    }
    data["iface_descr"] = get_iface_descr_map()

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

        now = int(time.time())
        row = db.execute(
            "SELECT COUNT(*) FROM selfcare_entries WHERE removed_ts IS NULL AND expires_ts > ?",
            (now,),
        ).fetchone()
        data["selfcare_active"] = row[0] if row else 0
        row = db.execute("SELECT COUNT(*) FROM selfcare_entries").fetchone()
        data["selfcare_total"] = row[0] if row else 0

        row = db.execute("SELECT COUNT(*) FROM permaban").fetchone()
        data["permaban_count"] = row[0] if row else 0

        # Per-interface aggregations. iface column may hold a comma-separated
        # list (one IP can hit multiple interfaces in load-balance setups), so
        # we explode it in Python — SQLite has no direct split-aggregate.
        sca_active = Counter()
        for r in db.execute(
            "SELECT iface FROM selfcare_entries WHERE removed_ts IS NULL AND expires_ts > ?",
            (now,),
        ):
            for i in _split_ifaces(r[0]):
                sca_active[i] += 1
        data["by_iface"]["selfcare_active"] = dict(sca_active)

        sca_total = Counter()
        for r in db.execute("SELECT iface FROM selfcare_entries"):
            for i in _split_ifaces(r[0]):
                sca_total[i] += 1
        data["by_iface"]["selfcare_total"] = dict(sca_total)

        rep_today = Counter()
        for r in db.execute(
            "SELECT iface FROM reports WHERE ts >= ? AND ok = 1", (midnight,)
        ):
            for i in _split_ifaces(r[0]):
                rep_today[i] += 1
        data["by_iface"]["reports_today"] = dict(rep_today)

        rep_total = Counter()
        for r in db.execute("SELECT iface FROM reports WHERE ok = 1"):
            for i in _split_ifaces(r[0]):
                rep_total[i] += 1
        data["by_iface"]["reports_total"] = dict(rep_total)

        # 14-day timeseries — bucket reports/selfcare adds by local day.
        # Pre-fill all 14 days with zero so the chart has a consistent x-axis.
        days = []
        bucket_reports = {}
        bucket_selfcare = {}
        for n in range(13, -1, -1):
            day_ts = midnight - n * 86400
            day_label = time.strftime("%Y-%m-%d", time.localtime(day_ts))
            days.append((day_ts, day_label))
            bucket_reports[day_label] = 0
            bucket_selfcare[day_label] = 0

        oldest = days[0][0]
        for r in db.execute(
            "SELECT ts FROM reports WHERE ts >= ? AND ok = 1", (oldest,)
        ):
            day_label = time.strftime("%Y-%m-%d", time.localtime(r[0]))
            if day_label in bucket_reports:
                bucket_reports[day_label] += 1
        for r in db.execute(
            "SELECT added_ts FROM selfcare_entries WHERE added_ts >= ?", (oldest,)
        ):
            day_label = time.strftime("%Y-%m-%d", time.localtime(r[0]))
            if day_label in bucket_selfcare:
                bucket_selfcare[day_label] += 1

        data["daily"]["reports"] = [
            {"day": lbl, "count": bucket_reports[lbl]} for _, lbl in days
        ]
        data["daily"]["selfcare_added"] = [
            {"day": lbl, "count": bucket_selfcare[lbl]} for _, lbl in days
        ]

        db.close()

    out_json(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
