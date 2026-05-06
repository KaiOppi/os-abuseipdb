#!/usr/bin/env python3
"""
Remove an IP from the Perma-Block list (pf table + ledger).
Also clears its selfcare_history so a freshly unbanned IP starts at zero.

Args: <ip>

Copyright (c) 2026 Kai Schlestein
BSD 2-Clause.
"""
import subprocess
import sys

from _common import PF_TABLE_PERMABAN, get_db, log, out_json


def main() -> int:
    if len(sys.argv) < 2:
        out_json({"status": "error", "message": "missing ip argument"})
        return 1
    ip = sys.argv[1].strip()

    db = get_db()
    cur = db.execute("DELETE FROM permaban WHERE ip = ?", (ip,))
    deleted = cur.rowcount
    # Reset history so the IP doesn't trip the threshold immediately.
    db.execute("DELETE FROM selfcare_history WHERE ip = ?", (ip,))
    db.commit()
    db.close()

    try:
        subprocess.run(
            ["/sbin/pfctl", "-t", PF_TABLE_PERMABAN, "-T", "delete", ip],
            check=False, capture_output=True, timeout=5,
        )
    except Exception as exc:
        log(f"permaban pfctl delete {ip} failed: {exc}")

    log(f"permaban remove {ip} (db_rows={deleted})")
    out_json({"status": "ok", "ip": ip, "removed": deleted})
    return 0


if __name__ == "__main__":
    sys.exit(main())
