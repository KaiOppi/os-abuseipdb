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


def parse_target(s: str):
    """Return (canonical_str, network_or_None) for a single IP or a CIDR
    range, or (None, None) when the string is neither.

    v0.14.0 (#9): the whitelist accepts ranges now (e.g. a mobile carrier's
    IPv6 prefix 2a00:20::/32, whose addresses rotate per cell tower). A
    single address is stored in its canonical host form; a range in its
    canonical network form so DB + pfctl + containment checks all agree.
    """
    try:
        return str(ipaddress.ip_address(s)), None
    except ValueError:
        pass
    try:
        net = ipaddress.ip_network(s, strict=False)
        return str(net), net
    except ValueError:
        return None, None


def _contained(entry: str, net) -> bool:
    """True when a stored selfcare/permaban entry (a host IP or a CIDR)
    falls inside the whitelisted network `net`."""
    try:
        addr = ipaddress.ip_address(entry)
        return addr.version == net.version and addr in net
    except ValueError:
        pass
    try:
        sub = ipaddress.ip_network(entry, strict=False)
        return sub.version == net.version and sub.subnet_of(net)
    except ValueError:
        return False


def main() -> int:
    if len(sys.argv) < 2:
        out_json({"status": "error", "message": "missing ip argument"})
        return 1
    ip = sys.argv[1].strip()
    source = sys.argv[2].strip() if len(sys.argv) > 2 else "manual"
    note = sys.argv[3].strip() if len(sys.argv) > 3 else ""

    ip, net = parse_target(ip)
    if ip is None:
        out_json({"status": "error", "message": f"invalid ip or cidr: {sys.argv[1].strip()}"})
        return 1

    db = get_db()
    now = int(time.time())

    existing = db.execute("SELECT 1 FROM whitelist WHERE ip = ?", (ip,)).fetchone()
    db.execute(
        "INSERT OR REPLACE INTO whitelist (ip, added_ts, source, note) "
        "VALUES (?, COALESCE((SELECT added_ts FROM whitelist WHERE ip = ?), ?), ?, ?)",
        (ip, ip, now, source, note),
    )

    # Determine which already-blocked entries this whitelist add should lift.
    # For a single IP that's an exact match; for a CIDR it's every active
    # selfcare entry and every permaban entry contained in the range (the
    # operator just said "this whole range is fine" — e.g. Constantin's
    # Vodafone IPv6 prefix of previously-blocked mobile clients, #9).
    if net is None:
        sc_targets = [ip]
        pb_targets = [ip]
    else:
        sc_targets = [r[0] for r in db.execute(
            "SELECT ip FROM selfcare_entries WHERE removed_ts IS NULL").fetchall()
            if _contained(r[0], net)]
        pb_targets = [r[0] for r in db.execute(
            "SELECT ip FROM permaban").fetchall() if _contained(r[0], net)]

    # Side-effect 1: lift any active selfcare entry (with pfctl). The
    # operator just said this IP/range is fine — don't keep blocking it.
    lifted_selfcare = 0
    for t in sc_targets:
        lifted_selfcare += db.execute(
            "UPDATE selfcare_entries SET removed_ts = ? "
            "WHERE ip = ? AND removed_ts IS NULL",
            (now, t),
        ).rowcount
        subprocess.run(
            ["/sbin/pfctl", "-t", PF_TABLE_SELFCARE, "-T", "delete", t],
            check=False, capture_output=True, timeout=5,
        )

    # Side-effect 2: remove from permaban if present (it was a manual/auto
    # decision; whitelisting overrides it).
    lifted_permaban = 0
    for t in pb_targets:
        lifted_permaban += db.execute(
            "DELETE FROM permaban WHERE ip = ?", (t,)
        ).rowcount
        subprocess.run(
            ["/sbin/pfctl", "-t", PF_TABLE_PERMABAN, "-T", "delete", t],
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
