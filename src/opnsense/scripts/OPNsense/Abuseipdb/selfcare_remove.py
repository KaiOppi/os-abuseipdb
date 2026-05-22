#!/usr/bin/env python3
"""
Remove an IP from the self-defense list, or clear the whole list.

Args:
    <ip>       — remove just this IP from selfcare_entries + pf table
    "all"      — clear every active selfcare entry (with confirm via the
                 second argument literal token "yes")

Copyright (c) 2026 Kai Schlestein
BSD 2-Clause.
"""
import subprocess
import sys
import time

from _common import PF_TABLE_SELFCARE, get_db, log, out_json


def pfctl_delete(ip: str) -> None:
    subprocess.run(
        ["/sbin/pfctl", "-t", PF_TABLE_SELFCARE, "-T", "delete", ip],
        check=False, capture_output=True, timeout=5,
    )


def main() -> int:
    if len(sys.argv) < 2:
        out_json({"status": "error", "message": "missing ip argument"})
        return 1
    arg = sys.argv[1].strip()
    now = int(time.time())
    db = get_db()

    if arg.lower() == "all":
        # Safety: caller must pass the literal token "yes" as the second
        # arg to prove this is intentional. The UI passes it; a curl from
        # the shell needs to be explicit.
        if len(sys.argv) < 3 or sys.argv[2].strip().lower() != "yes":
            out_json({"status": "error",
                      "message": "clear-all requires confirmation token 'yes' as 2nd argument"})
            return 1
        rows = db.execute(
            "SELECT ip FROM selfcare_entries WHERE removed_ts IS NULL AND expires_ts > ?",
            (now,),
        ).fetchall()
        for (ip,) in rows:
            pfctl_delete(ip)
        db.execute(
            "UPDATE selfcare_entries SET removed_ts = ? "
            "WHERE removed_ts IS NULL AND expires_ts > ?",
            (now, now),
        )
        db.commit()
        db.close()
        log(f"selfcare clear-all removed {len(rows)} entries")
        out_json({"status": "ok", "removed": len(rows), "mode": "all"})
        return 0

    ip = arg
    cur = db.execute(
        "UPDATE selfcare_entries SET removed_ts = ? "
        "WHERE ip = ? AND removed_ts IS NULL",
        (now, ip),
    )
    affected = cur.rowcount
    db.commit()
    db.close()
    pfctl_delete(ip)
    log(f"selfcare manual remove {ip} (db_rows={affected})")
    out_json({"status": "ok", "ip": ip, "removed": affected})
    return 0


if __name__ == "__main__":
    sys.exit(main())
