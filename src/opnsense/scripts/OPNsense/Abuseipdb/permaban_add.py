#!/usr/bin/env python3
"""
Add an IP to the Perma-Block list (pf table + ledger). Idempotent.
Also removes the IP from the Self-Defense list/table if present, since
permaban supersedes the TTL-bound block.

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
    """Accept any well-formed IPv4 or IPv6 address. The string form returned
    by ipaddress.ip_address() is the canonical form pfctl + sqlite agree on."""
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
        out_json({"status": "error", "message": f"invalid ip address: {ip}"})
        return 1
    # Normalise to the canonical string form so pfctl and the DB agree on
    # representation (e.g. "2001:0db8::1" → "2001:db8::1").
    ip = str(ipaddress.ip_address(ip))

    db = get_db()
    now = int(time.time())

    existing = db.execute("SELECT 1 FROM permaban WHERE ip = ?", (ip,)).fetchone()
    db.execute(
        "INSERT OR REPLACE INTO permaban (ip, added_ts, source, note) "
        "VALUES (?, COALESCE((SELECT added_ts FROM permaban WHERE ip = ?), ?), ?, ?)",
        (ip, ip, now, source, note),
    )

    # pfctl add to permaban table
    try:
        subprocess.run(
            ["/sbin/pfctl", "-t", PF_TABLE_PERMABAN, "-T", "add", ip],
            check=False, capture_output=True, timeout=5,
        )
    except Exception as exc:
        log(f"permaban pfctl add {ip} failed: {exc}")

    # Lift any selfcare entry — permaban replaces it.
    db.execute(
        "UPDATE selfcare_entries SET removed_ts = ? "
        "WHERE ip = ? AND removed_ts IS NULL",
        (now, ip),
    )
    try:
        subprocess.run(
            ["/sbin/pfctl", "-t", PF_TABLE_SELFCARE, "-T", "delete", ip],
            check=False, capture_output=True, timeout=5,
        )
    except Exception:
        pass

    db.commit()
    db.close()
    log(f"permaban add {ip} (source={source})")
    out_json({"status": "ok", "ip": ip, "newly_added": existing is None})
    return 0


if __name__ == "__main__":
    sys.exit(main())
