#!/usr/bin/env python3
"""
Add an IP to the operator-managed whitelist. Side-effect: also lifts the
IP out of selfcare + permaban (if present), so the operator's intent —
"this IP is fine, leave it alone" — applies retroactively.

Args: <ip> [source] [note]

Copyright (c) 2026 Kai Schlestein
BSD 2-Clause.
"""
import ipaddress
import subprocess
import sys
import time

from _common import (PF_TABLE_PERMABAN, PF_TABLE_SELFCARE, get_db, log,
                     out_json)


def is_valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def main() -> int:
    if len(sys.argv) < 2:
        out_json({"status": "error", "message": "missing ip argument"})
        return 1
    ip = sys.argv[1].strip()
    source = sys.argv[2].strip() if len(sys.argv) > 2 else "manual"
    note = sys.argv[3].strip() if len(sys.argv) > 3 else ""

    if not is_valid_ip(ip):
        out_json({"status": "error", "message": f"invalid ip: {ip}"})
        return 1
    # Canonical string form so DB + pfctl always agree.
    ip = str(ipaddress.ip_address(ip))

    db = get_db()
    now = int(time.time())

    existing = db.execute("SELECT 1 FROM whitelist WHERE ip = ?", (ip,)).fetchone()
    db.execute(
        "INSERT OR REPLACE INTO whitelist (ip, added_ts, source, note) "
        "VALUES (?, COALESCE((SELECT added_ts FROM whitelist WHERE ip = ?), ?), ?, ?)",
        (ip, ip, now, source, note),
    )

    # Side-effect 1: lift any active selfcare entry (with pfctl). The
    # operator just said this IP is fine — don't keep blocking it.
    lifted_selfcare = db.execute(
        "UPDATE selfcare_entries SET removed_ts = ? "
        "WHERE ip = ? AND removed_ts IS NULL",
        (now, ip),
    ).rowcount
    if lifted_selfcare:
        subprocess.run(
            ["/sbin/pfctl", "-t", PF_TABLE_SELFCARE, "-T", "delete", ip],
            check=False, capture_output=True, timeout=5,
        )

    # Side-effect 2: remove from permaban if present (it was a manual
    # decision; whitelisting overrides it).
    lifted_permaban = db.execute(
        "DELETE FROM permaban WHERE ip = ?", (ip,)
    ).rowcount
    if lifted_permaban:
        subprocess.run(
            ["/sbin/pfctl", "-t", PF_TABLE_PERMABAN, "-T", "delete", ip],
            check=False, capture_output=True, timeout=5,
        )

    db.commit()
    db.close()
    log(f"whitelist add {ip} (source={source}, lifted_selfcare={lifted_selfcare}, "
        f"lifted_permaban={lifted_permaban})")
    out_json({
        "status": "ok",
        "ip": ip,
        "newly_added": existing is None,
        "lifted_selfcare": lifted_selfcare,
        "lifted_permaban": lifted_permaban,
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
