#!/usr/bin/env python3
"""
Expire entries from the self-defense pf table once their TTL is up.

Copyright (c) 2026 Kai Schlestein
BSD 2-Clause.

Runs hourly from cron. Pulls the current pf table and the SQLite ledger,
removes anything whose expires_ts has passed, and also re-syncs the pf table
with the ledger (handles reboots, manual pfctl flushes, TTL changes).
"""
import subprocess
import sys
import time

from _common import PF_TABLE_SELFCARE, get_config, get_db, log


def pfctl_current() -> set[str]:
    try:
        r = subprocess.run(
            ["/sbin/pfctl", "-t", PF_TABLE_SELFCARE, "-T", "show"],
            check=False, capture_output=True, text=True, timeout=10,
        )
        return {line.strip() for line in r.stdout.splitlines() if line.strip()}
    except Exception as exc:
        log(f"selfcare cleanup: pfctl show failed: {exc}")
        return set()


def pfctl_delete(ip: str) -> None:
    subprocess.run(
        ["/sbin/pfctl", "-t", PF_TABLE_SELFCARE, "-T", "delete", ip],
        check=False, capture_output=True, timeout=5,
    )


def pfctl_add(ip: str) -> None:
    subprocess.run(
        ["/sbin/pfctl", "-t", PF_TABLE_SELFCARE, "-T", "add", ip],
        check=False, capture_output=True, timeout=5,
    )


def main() -> int:
    cfg = get_config()
    if cfg["general"]["enabled"] != "1" or cfg["selfcare"]["enabled"] != "1":
        print("selfcare disabled")
        return 0

    db = get_db()
    now = int(time.time())

    # Expire due entries
    expired = db.execute(
        "SELECT ip FROM selfcare_entries WHERE removed_ts IS NULL AND expires_ts <= ?",
        (now,),
    ).fetchall()
    for (ip,) in expired:
        pfctl_delete(ip)
        db.execute(
            "UPDATE selfcare_entries SET removed_ts = ? WHERE ip = ?",
            (now, ip),
        )
    db.commit()

    # Re-sync: anything active in ledger but missing in pf gets re-added
    active = {
        row[0] for row in db.execute(
            "SELECT ip FROM selfcare_entries WHERE removed_ts IS NULL AND expires_ts > ?",
            (now,),
        ).fetchall()
    }
    current = pfctl_current()
    missing = active - current
    stale = current - active  # unexpected extras in pf — leave alone (admin-added)
    for ip in missing:
        pfctl_add(ip)

    log(f"selfcare cleanup: expired={len(expired)} active={len(active)} re-added={len(missing)}")
    print(f"expired={len(expired)} active={len(active)} re-added={len(missing)}")
    db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
