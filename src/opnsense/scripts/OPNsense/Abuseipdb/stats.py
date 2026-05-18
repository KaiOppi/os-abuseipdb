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
        # v0.8: IPv6-only subset of the same counters, so the UI can render
        # stacked bars (v4 + v6). totals stay in by_iface; v4 share is
        # implicit (by_iface[k] - by_iface_v6[k]).
        "by_iface_v6": {
            "selfcare_active": {},
            "selfcare_total": {},
            "reports_today": {},
            "reports_total": {},
        },
        "daily": {                  # last 14 days, oldest → newest
            "reports": [],
            "selfcare_added": [],
        },
        # v0.8: per-endpoint API quota from the most recent header we saw
        "quota": {                  # endpoint → {remaining, limit, reset_ts, last_seen}
            "report":    {"remaining": None, "limit": None, "reset_ts": None, "last_seen": None},
            "check":     {"remaining": None, "limit": None, "reset_ts": None, "last_seen": None},
            "blacklist": {"remaining": None, "limit": None, "reset_ts": None, "last_seen": None},
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

        # v0.8: latest header per endpoint
        for endpoint in ("report", "check", "blacklist"):
            q = db.execute(
                "SELECT ts, remaining, rate_limit, reset_ts FROM api_quota_log "
                "WHERE endpoint = ? ORDER BY ts DESC LIMIT 1",
                (endpoint,),
            ).fetchone()
            if q:
                data["quota"][endpoint] = {
                    "last_seen": q[0],
                    "remaining": q[1],
                    "limit": q[2],
                    "reset_ts": q[3],
                }

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

        # v0.8: snapshot history (last N entries, newest first). Empty when
        # the user runs replace or persist-days mode, populated under
        # union/intersection. The UI only renders this section when there
        # is at least one entry, so we don't have to know the mode here.
        snaps = db.execute(
            "SELECT snapshot_id, fetched_ts, ip_count, quota_remaining "
            "FROM blacklist_snapshot_meta "
            "ORDER BY snapshot_id DESC LIMIT 30"
        ).fetchall()
        data["snapshots"] = [
            {"id": r[0], "fetched_ts": r[1], "ip_count": r[2], "quota_remaining": r[3]}
            for r in snaps
        ]

        # Per-interface aggregations. iface column may hold a comma-separated
        # list (one IP can hit multiple interfaces in load-balance setups), so
        # we explode it in Python — SQLite has no direct split-aggregate.
        # v0.8: also count the v6-only subset separately so the UI can render
        # stacked v4+v6 bars. v6 detection by ':' in the ip column.
        sca_active   = Counter(); sca_active_v6   = Counter()
        for r in db.execute(
            "SELECT iface, ip FROM selfcare_entries WHERE removed_ts IS NULL AND expires_ts > ?",
            (now,),
        ):
            is_v6 = r[1] and ":" in r[1]
            for i in _split_ifaces(r[0]):
                sca_active[i] += 1
                if is_v6:
                    sca_active_v6[i] += 1
        data["by_iface"]["selfcare_active"]    = dict(sca_active)
        data["by_iface_v6"]["selfcare_active"] = dict(sca_active_v6)

        sca_total = Counter(); sca_total_v6 = Counter()
        for r in db.execute("SELECT iface, ip FROM selfcare_entries"):
            is_v6 = r[1] and ":" in r[1]
            for i in _split_ifaces(r[0]):
                sca_total[i] += 1
                if is_v6:
                    sca_total_v6[i] += 1
        data["by_iface"]["selfcare_total"]    = dict(sca_total)
        data["by_iface_v6"]["selfcare_total"] = dict(sca_total_v6)

        rep_today = Counter(); rep_today_v6 = Counter()
        for r in db.execute(
            "SELECT iface, ip FROM reports WHERE ts >= ? AND ok = 1", (midnight,)
        ):
            is_v6 = r[1] and ":" in r[1]
            for i in _split_ifaces(r[0]):
                rep_today[i] += 1
                if is_v6:
                    rep_today_v6[i] += 1
        data["by_iface"]["reports_today"]    = dict(rep_today)
        data["by_iface_v6"]["reports_today"] = dict(rep_today_v6)

        rep_total = Counter(); rep_total_v6 = Counter()
        for r in db.execute("SELECT iface, ip FROM reports WHERE ok = 1"):
            is_v6 = r[1] and ":" in r[1]
            for i in _split_ifaces(r[0]):
                rep_total[i] += 1
                if is_v6:
                    rep_total_v6[i] += 1
        data["by_iface"]["reports_total"]    = dict(rep_total)
        data["by_iface_v6"]["reports_total"] = dict(rep_total_v6)

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
        # v0.8: track the v6 share separately so the daily-chart bars in the
        # UI can render stacked v4+v6 segments like the per-interface bars.
        bucket_reports_v6 = {lbl: 0 for _, lbl in days}
        bucket_selfcare_v6 = {lbl: 0 for _, lbl in days}
        for r in db.execute(
            "SELECT ts, ip FROM reports WHERE ts >= ? AND ok = 1", (oldest,)
        ):
            day_label = time.strftime("%Y-%m-%d", time.localtime(r[0]))
            if day_label in bucket_reports:
                bucket_reports[day_label] += 1
                if r[1] and ":" in r[1]:
                    bucket_reports_v6[day_label] += 1
        for r in db.execute(
            "SELECT added_ts, ip FROM selfcare_entries WHERE added_ts >= ?", (oldest,)
        ):
            day_label = time.strftime("%Y-%m-%d", time.localtime(r[0]))
            if day_label in bucket_selfcare:
                bucket_selfcare[day_label] += 1
                if r[1] and ":" in r[1]:
                    bucket_selfcare_v6[day_label] += 1

        data["daily"]["reports"] = [
            {"day": lbl, "count": bucket_reports[lbl],
             "count_v6": bucket_reports_v6[lbl]}
            for _, lbl in days
        ]
        data["daily"]["selfcare_added"] = [
            {"day": lbl, "count": bucket_selfcare[lbl],
             "count_v6": bucket_selfcare_v6[lbl]}
            for _, lbl in days
        ]

        db.close()

    out_json(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
