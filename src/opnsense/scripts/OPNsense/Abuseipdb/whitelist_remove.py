#!/usr/bin/env python3
"""
Remove an IP from the operator-managed whitelist.

Args: <ip>

Copyright (c) 2026 Kai Schlestein
BSD 2-Clause.
"""
import sys

from _common import get_db, log, out_json


def main() -> int:
    if len(sys.argv) < 2:
        out_json({"status": "error", "message": "missing ip argument"})
        return 1
    ip = sys.argv[1].strip()

    db = get_db()
    cur = db.execute("DELETE FROM whitelist WHERE ip = ?", (ip,))
    deleted = cur.rowcount
    db.commit()
    db.close()
    log(f"whitelist remove {ip} (db_rows={deleted})")
    out_json({"status": "ok", "ip": ip, "removed": deleted})
    return 0


if __name__ == "__main__":
    sys.exit(main())
