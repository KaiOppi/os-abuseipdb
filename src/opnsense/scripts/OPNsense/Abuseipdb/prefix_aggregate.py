#!/usr/bin/env python3
"""
Aggregate self-defense hits into prefix-level blocks (issue #8).

Copyright (c) 2026 Kai Schlestein
BSD 2-Clause.

IPv6 attacks typically arrive in waves from the same prefix — an attacker
holding a /64 (or larger) just rotates through addresses, so blocking the
individual /128s is whack-a-mole. This scan groups the individual IPs that
the reporters already dropped into self-defense by prefix (default /64 for
IPv6, /24 for IPv4) and, once `threshold` distinct addresses from one prefix
have been seen within `window_hours`, blocks the WHOLE prefix locally in the
pf table instead.

Escalation (mirrors the per-IP self-defense -> perma-block model, one level up):
  1. threshold distinct IPs from a prefix within the window
        -> add the prefix to self-defense (pf table + DB) with the normal TTL.
  2. TTL expires -> the prefix is unblocked again (self-defense cleanup).
  3. Each further wave (threshold fresh IPs after the previous aggregation)
     bumps the prefix's wave counter; once it reaches `permaban_after`
     the whole prefix is promoted to the perma-block list.

Reporting to AbuseIPDB stays strictly per-IP — the /report API takes no CIDR,
and each rotated address is genuine independent evidence. This script only
touches the LOCAL pf tables.

Safety: a prefix that contains any operator-whitelisted IP is never blocked.
The feature is opt-in and requires self-defense to be enabled (it writes into
the self-defense pf table / alias).
"""
import ipaddress
import subprocess
import sys
import time
from collections import defaultdict

from _common import (PF_TABLE_PERMABAN, PF_TABLE_SELFCARE, get_config, get_db,
                     log)


def pf_add(table: str, entry: str) -> None:
    try:
        subprocess.run(["/sbin/pfctl", "-t", table, "-T", "add", entry],
                       check=False, capture_output=True, timeout=5)
    except Exception as exc:
        log(f"aggregate pfctl add {entry} -> {table} failed: {exc}")


def pf_del(table: str, entry: str) -> None:
    try:
        subprocess.run(["/sbin/pfctl", "-t", table, "-T", "delete", entry],
                       check=False, capture_output=True, timeout=5)
    except Exception as exc:
        log(f"aggregate pfctl delete {entry} <- {table} failed: {exc}")


def main() -> int:
    cfg = get_config()
    if cfg["general"]["enabled"] != "1":
        print("plugin disabled")
        return 0
    if cfg["aggregate"]["enabled"] != "1":
        print("aggregate disabled")
        return 0
    if cfg["selfcare"]["enabled"] != "1":
        # We write into the self-defense pf table / alias, which only exists
        # when self-defense is enabled.
        print("aggregate requires self-defense enabled")
        return 0

    plen6 = max(48, min(64, int(cfg["aggregate"]["prefix_v6"])))
    plen4 = max(16, min(30, int(cfg["aggregate"]["prefix_v4"])))
    threshold = max(2, int(cfg["aggregate"]["threshold"]))
    window = max(1, int(cfg["aggregate"]["window_hours"])) * 3600
    permaban_after = int(cfg["aggregate"]["permaban_after"])
    permaban_on = cfg["permaban"]["enabled"] == "1"
    ttl = int(cfg["selfcare"]["ttl_hours"]) * 3600

    db = get_db()
    now = int(time.time())
    window_start = now - window

    # Whitelisted addresses — never block a prefix that contains one.
    whitelist = []
    for r in db.execute("SELECT ip FROM whitelist"):
        try:
            whitelist.append(ipaddress.ip_address(r[0]))
        except ValueError:
            pass

    # Individual self-defense IPs added within the window. Exclude the CIDR
    # entries this script itself writes (they contain '/').
    rows = db.execute(
        "SELECT ip, added_ts FROM selfcare_entries "
        "WHERE ip NOT LIKE '%/%' AND added_ts >= ?",
        (window_start,),
    ).fetchall()

    # Group (ip, added_ts) tuples by prefix.
    groups: dict = defaultdict(lambda: {"members": set(), "family": None})
    for ip_str, added_ts in rows:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        plen = plen6 if ip.version == 6 else plen4
        try:
            net = ipaddress.ip_network(f"{ip_str}/{plen}", strict=False)
        except ValueError:
            continue
        key = str(net)
        groups[key]["members"].add((ip_str, int(added_ts)))
        groups[key]["family"] = ip.version

    aggregated = 0
    promoted = 0
    for prefix, info in groups.items():
        net = ipaddress.ip_network(prefix, strict=False)
        family = info["family"]

        row = db.execute(
            "SELECT agg_count, last_agg_ts, permabanned_ts "
            "FROM prefix_aggregate WHERE prefix = ?",
            (prefix,),
        ).fetchone()
        agg_count = row[0] if row else 0
        last_agg_ts = (row[1] or 0) if row else 0
        permabanned_ts = row[2] if row else None

        if permabanned_ts:
            # Already permanently blocked — nothing more to do.
            continue

        # A fresh wave = distinct IPs added AFTER the previous aggregation
        # (and within the window). This is what "X further attacks" means.
        effective_since = max(window_start, last_agg_ts)
        fresh = {ip for (ip, ts) in info["members"] if ts >= effective_since}
        if len(fresh) < threshold:
            continue

        # Safety: never block a prefix that swallows a whitelisted IP.
        if any(w in net for w in whitelist):
            log(f"aggregate skip {prefix}: contains a whitelisted IP")
            continue

        agg_count += 1
        if row is None:
            db.execute(
                "INSERT INTO prefix_aggregate "
                "(prefix, family, first_seen_ts, last_agg_ts, agg_count) "
                "VALUES (?, ?, ?, ?, ?)",
                (prefix, family, now, now, agg_count),
            )
        else:
            db.execute(
                "UPDATE prefix_aggregate SET last_agg_ts = ?, agg_count = ? "
                "WHERE prefix = ?",
                (now, agg_count, prefix),
            )

        promote = permaban_on and permaban_after > 0 and agg_count >= permaban_after
        if promote:
            db.execute(
                "INSERT OR REPLACE INTO permaban (ip, added_ts, source, note) "
                "VALUES (?, ?, ?, ?)",
                (prefix, now, "aggregate-prefix",
                 f"{len(fresh)} IPs in wave #{agg_count}"),
            )
            pf_add(PF_TABLE_PERMABAN, prefix)
            db.execute(
                "UPDATE prefix_aggregate SET permabanned_ts = ? WHERE prefix = ?",
                (now, prefix),
            )
            # Lift any active self-defense CIDR entry — perma-block supersedes it.
            db.execute(
                "UPDATE selfcare_entries SET removed_ts = ? "
                "WHERE ip = ? AND removed_ts IS NULL",
                (now, prefix),
            )
            pf_del(PF_TABLE_SELFCARE, prefix)
            promoted += 1
            log(f"aggregate PERMABAN {prefix} (wave #{agg_count}, "
                f"{len(fresh)} fresh IPs)")
        else:
            expires = now + ttl
            db.execute(
                "INSERT OR REPLACE INTO selfcare_entries "
                "(ip, added_ts, expires_ts, source, categories, iface, removed_ts) "
                "VALUES (?, ?, ?, ?, ?, ?, NULL)",
                (prefix, now, expires, "aggregate", "", ""),
            )
            pf_add(PF_TABLE_SELFCARE, prefix)
            aggregated += 1
            log(f"aggregate SELF-DEFENSE {prefix} (wave #{agg_count}, "
                f"{len(fresh)} fresh IPs, ttl {ttl // 3600}h)")

    db.commit()
    db.close()
    print(f"prefix aggregate done: {aggregated} prefix self-defense blocks, "
          f"{promoted} promoted to perma-block")
    return 0


if __name__ == "__main__":
    sys.exit(main())
