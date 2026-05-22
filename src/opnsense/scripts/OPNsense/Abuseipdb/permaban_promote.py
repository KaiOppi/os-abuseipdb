#!/usr/bin/env python3
"""
Auto-promote scan: walk selfcare_history and promote any IP with
occurrences >= threshold whose last_seen_ts is within the configured window.

Also re-syncs the pf table from the ledger (handles reboot, manual flush).

Copyright (c) 2026 Kai Schlestein
BSD 2-Clause.
"""
import subprocess
import sys
import time

from _common import (PF_TABLE_PERMABAN, get_config, get_db, is_whitelisted,
                     log, out_json, record_whitelist_skip)


def pfctl_add(ip: str) -> None:
    subprocess.run(
        ["/sbin/pfctl", "-t", PF_TABLE_PERMABAN, "-T", "add", ip],
        check=False, capture_output=True, timeout=5,
    )


def pfctl_show() -> set[str]:
    try:
        r = subprocess.run(
            ["/sbin/pfctl", "-t", PF_TABLE_PERMABAN, "-T", "show"],
            check=False, capture_output=True, text=True, timeout=10,
        )
        return {line.strip() for line in r.stdout.splitlines() if line.strip()}
    except Exception:
        return set()


def main() -> int:
    cfg = get_config()
    if cfg["general"]["enabled"] != "1" or cfg["permaban"]["enabled"] != "1":
        out_json({"status": "ok", "promoted": 0, "message": "permaban disabled"})
        return 0

    threshold = max(2, int(cfg["permaban"]["promote_threshold"]))
    window_days = max(1, int(cfg["permaban"]["promote_window_days"]))
    window_sec = window_days * 86400

    db = get_db()
    now = int(time.time())
    cutoff = now - window_sec

    # Candidates: enough occurrences, last seen within window, not already permabanned.
    rows = db.execute(
        "SELECT h.ip, h.occurrences, h.last_seen_ts "
        "FROM selfcare_history h "
        "LEFT JOIN permaban p ON p.ip = h.ip "
        "WHERE p.ip IS NULL "
        "  AND h.occurrences >= ? "
        "  AND h.last_seen_ts >= ?",
        (threshold, cutoff),
    ).fetchall()

    promoted = []
    skipped_wl = 0
    for ip, occ, last_ts in rows:
        # v0.9.0: never promote whitelisted IPs — operator intent overrules.
        if is_whitelisted(db, ip):
            record_whitelist_skip(db, ip, "permaban-promote")
            skipped_wl += 1
            log(f"permaban promote skip {ip} — whitelisted")
            continue
        last_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(last_ts))
        db.execute(
            "INSERT OR REPLACE INTO permaban (ip, added_ts, source, note) "
            "VALUES (?, ?, ?, ?)",
            (ip, now, "auto-promote",
             f"{occ} selfcare hits within {window_days}d, last {last_str}"),
        )
        pfctl_add(ip)
        promoted.append(ip)
        log(f"permaban auto-promote {ip} ({occ} hits in {window_days}d)")
    db.commit()

    # Resync: re-add any ledger entries missing in pf (post-reboot etc.)
    ledger = {row[0] for row in db.execute("SELECT ip FROM permaban").fetchall()}
    table = pfctl_show()
    missing = ledger - table
    for ip in missing:
        pfctl_add(ip)

    db.close()
    out_json({
        "status": "ok",
        "promoted": len(promoted),
        "resynced": len(missing),
        "skipped_whitelist": skipped_wl,
        "ips": promoted,
        "threshold": threshold,
        "window_days": window_days,
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
