#!/usr/bin/env python3
"""
Sample pf counters for the permaban table and persist deltas in the DB so
hit-counts survive reboots.

Copyright (c) 2026 Kai Schlestein
BSD 2-Clause.

Runs from cron every 5 min. Reads `pfctl -t abuseipdb_permaban -T show -vv`,
computes the per-IP delta against the last sampled value, and adds it to
`cumulative_hits`. A reboot resets the kernel counters to zero — detected as
`current < pf_last_seen` and treated as `delta = current` (everything since
boot is new).

Cost: a single pfctl read of an in-memory kernel struct, plus N small
UPDATEs. For typical permaban-tables (<100 IPs) this finishes in <50 ms.
"""
import re
import subprocess
import sys
import time

from _common import PF_TABLE_PERMABAN, get_db, log


# Match a leading-whitespace bare IP (table entry header) — IPv4 only for now.
# pfctl prints them with 3-space indent, no other content on the line.
_IP_LINE = re.compile(r"^\s+(\d{1,3}(?:\.\d{1,3}){3})\s*$")
_PACKETS = re.compile(r"Packets:\s+(\d+)")


def pfctl_counters() -> dict[str, int]:
    """Return {ip: total_packets} for every entry in the permaban pf table.

    Total packets = In/Block + In/Pass + Out/Block + Out/Pass — every match
    against the table counts as a "hit", regardless of direction or verdict.
    Block-rules in front of this table mean Pass-counters stay at 0 in
    practice, but we sum them all to be future-proof.
    """
    try:
        r = subprocess.run(
            ["/sbin/pfctl", "-t", PF_TABLE_PERMABAN, "-T", "show", "-vv"],
            check=False, capture_output=True, text=True, timeout=15,
        )
    except Exception as exc:
        log(f"permaban_count: pfctl read failed: {exc}")
        return {}
    if r.returncode != 0:
        log(f"permaban_count: pfctl rc={r.returncode}: {r.stderr.strip()[:200]}")
        return {}

    counters: dict[str, int] = {}
    current_ip: str | None = None
    for line in r.stdout.splitlines():
        m = _IP_LINE.match(line)
        if m:
            current_ip = m.group(1)
            counters[current_ip] = 0
            continue
        if current_ip and "Packets:" in line:
            pm = _PACKETS.search(line)
            if pm:
                counters[current_ip] += int(pm.group(1))
    return counters


def main() -> int:
    db = get_db()
    now = int(time.time())
    sampled = pfctl_counters()

    rows = db.execute("SELECT ip, pf_last_seen, cumulative_hits FROM permaban").fetchall()
    if not rows:
        log("permaban_count: no entries — skipping")
        print("no permaban entries")
        db.close()
        return 0

    advanced = 0
    reboot_detected = 0
    for ip, last_seen, cumulative in rows:
        current = sampled.get(ip, 0)
        if current < last_seen:
            # Reboot or pfctl -T zero — counter restarted at zero.
            delta = current
            reboot_detected += 1
        else:
            delta = current - last_seen
        if delta > 0:
            db.execute(
                "UPDATE permaban "
                "SET cumulative_hits = cumulative_hits + ?, "
                "    pf_last_seen = ?, "
                "    last_hit_ts = ? "
                "WHERE ip = ?",
                (delta, current, now, ip),
            )
            advanced += 1
        elif current != last_seen:
            # No new hits but kernel counter shifted (typically post-reboot:
            # last_seen=42, current=0, delta=0 because of the reset branch
            # above only fires on current<last_seen — refresh the baseline).
            db.execute(
                "UPDATE permaban SET pf_last_seen = ? WHERE ip = ?",
                (current, ip),
            )
    db.commit()

    log(f"permaban_count: rows={len(rows)} advanced={advanced} reboot_detected={reboot_detected}")
    print(f"rows={len(rows)} advanced={advanced} reboot_detected={reboot_detected}")
    db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
