#!/usr/bin/env python3
"""
Download the AbuseIPDB blacklist into a local file for OPNsense URL Table Alias.

Copyright (c) 2026 Kai Schlestein
BSD 2-Clause.

The written file /var/db/abuseipdb/blocklist.txt can be referenced from OPNsense
as a "URL Table" Firewall Alias (one IP or network per line) — OPNsense then
loads it into its own pf table on commit.
"""
import os
import subprocess
import sys
import time
from _common import (
    API_BASE, BLOCKLIST_FILE, PF_TABLE,
    die, ensure_state_dir, get_config, get_db, log, record_quota,
)

try:
    import requests
except ImportError:
    die("Python requests library missing (install py311-requests).")


def _fetch_one(api_key: str, confidence_min: int, limit: int,
               ip_version: int | None) -> tuple[list[str], int | None]:
    """One call to /blacklist. `ip_version` None = whatever the API defaults to
    (in practice IPv4-only). Pass 4 or 6 to scope explicitly."""
    params = {"confidenceMinimum": confidence_min, "limit": limit}
    if ip_version in (4, 6):
        params["ipVersion"] = ip_version
    r = requests.get(
        f"{API_BASE}/blacklist",
        headers={"Key": api_key, "Accept": "text/plain"},
        params=params,
        timeout=45,
    )
    record_quota(None, "blacklist", r)
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")
    quota = r.headers.get("X-RateLimit-Remaining")
    try:
        quota_i = int(quota) if quota is not None else None
    except ValueError:
        quota_i = None
    ips = [line.strip() for line in r.text.splitlines() if line.strip()]
    return ips, quota_i


def fetch_blacklist(api_key: str, confidence_min: int, limit: int,
                    include_ipv6: bool) -> tuple[list[str], int | None]:
    """Return (ip_list, quota_remaining). Raises on non-2xx for the IPv4 call;
    a failure on the optional IPv6 call is soft (logged via the eventual
    record_run, IPv4 list is kept). Quota reported is the worse of the two.

    The AbuseIPDB blacklist endpoint defaults to IPv4-only (verified
    empirically 2026-05-16). When include_ipv6 is True we make a second
    explicit ipVersion=6 call and merge — this costs one extra blacklist
    quota slot per run."""
    v4, q = _fetch_one(api_key, confidence_min, limit, None)
    if not include_ipv6:
        return v4, q
    try:
        v6, q6 = _fetch_one(api_key, confidence_min, limit, 6)
    except RuntimeError as exc:
        # Don't lose the v4 list just because v6 hit a quota wall or a transient
        # error — let the caller proceed with v4-only and log the v6 problem.
        log(f"blacklist v6 fetch failed, keeping v4-only result: {exc}")
        return v4, q
    merged_quota = q if q6 is None else (q6 if q is None else min(q, q6))
    # Dedup while preserving original order (v4 first, then v6)
    seen = set()
    merged = []
    for ip in v4 + v6:
        if ip not in seen:
            seen.add(ip)
            merged.append(ip)
    return merged, merged_quota


def write_blocklist(ips: list[str]) -> None:
    ensure_state_dir()
    tmp = BLOCKLIST_FILE + ".tmp"
    with open(tmp, "w", encoding="ascii") as fh:
        fh.write("\n".join(ips))
        if ips:
            fh.write("\n")
    os.replace(tmp, BLOCKLIST_FILE)


def merge_into_persistent(db, fresh_ips: list[str], ttl_days: int) -> tuple[int, int, int]:
    """Merge today's download into the persistent table:
      - INSERT OR IGNORE the new IPs (first_seen stays at original ts).
      - UPDATE last_seen_ts for every IP we still see in today's pull
        — that's our heartbeat so the cleanup knows the IP is still on
        AbuseIPDB's radar.
      - DELETE rows whose first_seen_ts is older than ttl_days * 86400.
    Returns (added, refreshed, evicted).
    """
    import time as _time
    now = int(_time.time())
    added = 0
    refreshed = 0
    for ip in fresh_ips:
        cur = db.execute(
            "SELECT 1 FROM blacklist_persistent WHERE ip = ?", (ip,)
        ).fetchone()
        if cur is None:
            db.execute(
                "INSERT INTO blacklist_persistent (ip, first_seen_ts, last_seen_ts) "
                "VALUES (?, ?, ?)",
                (ip, now, now),
            )
            added += 1
        else:
            db.execute(
                "UPDATE blacklist_persistent SET last_seen_ts = ? WHERE ip = ?",
                (now, ip),
            )
            refreshed += 1
    # TTL on first_seen — once an IP has been in the persistent set for
    # ttl_days, it leaves regardless of whether AbuseIPDB still ships it.
    # That gives Constantin's "sleeper protection" a bounded memory cost.
    cutoff = now - ttl_days * 86400
    evicted = db.execute(
        "DELETE FROM blacklist_persistent WHERE first_seen_ts < ?", (cutoff,)
    ).rowcount or 0
    db.commit()
    return added, refreshed, evicted


def collect_persistent_ips(db) -> list[str]:
    """Return all IPs currently in the persistent table, ordered for stable
    output. pf doesn't care about order; this is purely for reproducibility
    in the blocklist file."""
    rows = db.execute(
        "SELECT ip FROM blacklist_persistent ORDER BY ip"
    ).fetchall()
    return [r[0] for r in rows]


# ── v0.8 snapshot-rotation helpers ─────────────────────────────────────────
#
# Each successful download becomes its own immutable snapshot. The active
# pf-alias is then derived from the last N snapshots:
#   - union mode         → "every IP we have seen in the last N runs"
#   - intersection mode  → "IP must appear in ≥ M of the last N runs"
#
# Default DB cost is bounded: at most N × max_ips rows in blacklist_snapshots,
# plus an index on (ip) so the GROUP BY ip HAVING COUNT(*) >= M query at
# alias-build time stays sub-second even at N=30, max_ips=10k.

def add_snapshot(db, ips: list[str], fetched_ts: int,
                 quota_remaining: int | None) -> int:
    """Persist `ips` as one new immutable snapshot. Returns the snapshot_id
    assigned by SQLite's AUTOINCREMENT. Caller is responsible for calling
    prune_old_snapshots() afterwards so the rolling window stays bounded."""
    cur = db.execute(
        "INSERT INTO blacklist_snapshot_meta (fetched_ts, ip_count, quota_remaining) "
        "VALUES (?, ?, ?)",
        (fetched_ts, len(ips), quota_remaining),
    )
    snapshot_id = cur.lastrowid
    if ips:
        db.executemany(
            "INSERT OR IGNORE INTO blacklist_snapshots (snapshot_id, ip) VALUES (?, ?)",
            [(snapshot_id, ip) for ip in ips],
        )
    db.commit()
    return snapshot_id


def prune_old_snapshots(db, keep_n: int) -> int:
    """Delete all snapshots older than the `keep_n` most recent. Returns
    the number of snapshots that got pruned (mostly for logging)."""
    keep_ids = [r[0] for r in db.execute(
        "SELECT snapshot_id FROM blacklist_snapshot_meta "
        "ORDER BY snapshot_id DESC LIMIT ?",
        (keep_n,),
    ).fetchall()]
    if not keep_ids:
        return 0
    placeholders = ",".join("?" for _ in keep_ids)
    db.execute(
        f"DELETE FROM blacklist_snapshots WHERE snapshot_id NOT IN ({placeholders})",
        keep_ids,
    )
    cur = db.execute(
        f"DELETE FROM blacklist_snapshot_meta WHERE snapshot_id NOT IN ({placeholders})",
        keep_ids,
    )
    db.commit()
    return cur.rowcount or 0


def compute_active_alias(db, history_mode: str, history_size: int,
                         history_threshold: int) -> tuple[list[str], int]:
    """Build the IP list that should populate the pf alias right now.

    Returns (ip_list, snapshots_considered).

    - union:        DISTINCT ip across the last `history_size` snapshots.
                    Equivalent to persist_days but with a fixed-size window
                    rather than a TTL.
    - intersection: ip must appear in at least `history_threshold` of the
                    last `history_size` snapshots. Caller's responsibility
                    to keep threshold <= history_size (model layer enforces).
    """
    snap_ids = [r[0] for r in db.execute(
        "SELECT snapshot_id FROM blacklist_snapshot_meta "
        "ORDER BY snapshot_id DESC LIMIT ?",
        (history_size,),
    ).fetchall()]
    if not snap_ids:
        return [], 0
    placeholders = ",".join("?" for _ in snap_ids)
    if history_mode == "union":
        sql = (f"SELECT ip FROM blacklist_snapshots "
               f"WHERE snapshot_id IN ({placeholders}) "
               f"GROUP BY ip ORDER BY ip")
        rows = db.execute(sql, snap_ids).fetchall()
    else:  # intersection
        threshold = min(history_threshold, len(snap_ids))
        sql = (f"SELECT ip FROM blacklist_snapshots "
               f"WHERE snapshot_id IN ({placeholders}) "
               f"GROUP BY ip HAVING COUNT(*) >= ? ORDER BY ip")
        rows = db.execute(sql, snap_ids + [threshold]).fetchall()
    return [r[0] for r in rows], len(snap_ids)


def reload_pf_table() -> str:
    """Reload the pf table if it exists. Returns a short status message."""
    # Table only exists if OPNsense has built it from a URL-table alias.
    # When the alias isn't configured yet, pfctl -t <name> returns an error.
    result = subprocess.run(
        ["/sbin/pfctl", "-t", PF_TABLE, "-T", "replace", "-f", BLOCKLIST_FILE],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        return "pf table refreshed"
    return f"pf table not refreshed (likely alias '{PF_TABLE}' not yet configured): {result.stderr.strip()}"


def record_run(ok: bool, ip_count: int, quota_remaining: int | None, message: str) -> None:
    db = get_db()
    db.execute(
        "INSERT OR REPLACE INTO blacklist_runs (ts, ok, ip_count, quota_remaining, message) VALUES (?, ?, ?, ?, ?)",
        (int(time.time()), 1 if ok else 0, ip_count, quota_remaining, message[:500]),
    )
    db.commit()
    db.close()


def main() -> int:
    cfg = get_config()
    if cfg["general"]["enabled"] != "1":
        print("plugin disabled — nothing to do")
        return 0
    if cfg["blacklist"]["enabled"] != "1":
        print("blacklist disabled — nothing to do")
        return 0

    api_key = cfg["general"]["api_key"].strip()
    if not api_key:
        record_run(False, 0, None, "no api key configured")
        die("No API key configured.")

    conf_min = int(cfg["blacklist"]["confidence_min"])
    max_ips = int(cfg["blacklist"]["max_ips"])
    include_ipv6 = cfg["blacklist"].get("include_ipv6", "0") == "1"
    persist_days = int(cfg["blacklist"].get("persist_days", "0"))
    history_mode = cfg["blacklist"].get("history_mode", "off")
    history_size = int(cfg["blacklist"].get("history_size", "7"))
    history_threshold = int(cfg["blacklist"].get("history_threshold", "4"))

    log(f"starting blacklist fetch (confidence={conf_min}, limit={max_ips}, "
        f"include_ipv6={include_ipv6}, persist_days={persist_days}, "
        f"history_mode={history_mode}, history_size={history_size}, "
        f"history_threshold={history_threshold})")
    try:
        fresh_ips, quota = fetch_blacklist(api_key, conf_min, max_ips, include_ipv6)
    except Exception as exc:
        record_run(False, 0, None, str(exc)[:200])
        die(f"fetch failed: {exc}")

    now = int(time.time())

    if history_mode in ("union", "intersection"):
        # v0.8 snapshot rotation. Each run is its own immutable snapshot;
        # the active pf-alias is computed from the last N snapshots either
        # as DISTINCT-ip (union) or count >= threshold (intersection).
        # This mode takes precedence over persist_days.
        db = get_db()
        snap_id = add_snapshot(db, fresh_ips, now, quota)
        pruned = prune_old_snapshots(db, history_size)
        active_ips, snaps_used = compute_active_alias(
            db, history_mode, history_size, history_threshold
        )
        db.close()
        write_blocklist(active_ips)
        pf_msg = reload_pf_table()
        msg = (f"{history_mode} mode: snap_id={snap_id} fresh={len(fresh_ips)}, "
               f"history={snaps_used}/{history_size}"
               + (f" threshold={history_threshold}" if history_mode == "intersection" else "")
               + f" → alias={len(active_ips)} IPs, pruned_snapshots={pruned}, "
               f"quota={quota}, {pf_msg}")
        record_run(True, len(active_ips), quota, msg)

    elif persist_days > 0:
        # v0.7 persistent mode (kept for back-compat). Keep every IP for
        # `persist_days`, refresh last_seen each time it reappears.
        db = get_db()
        added, refreshed, evicted = merge_into_persistent(db, fresh_ips, persist_days)
        merged_ips = collect_persistent_ips(db)
        db.close()
        write_blocklist(merged_ips)
        pf_msg = reload_pf_table()
        msg = (f"persistent mode: {len(fresh_ips)} fresh ({added} new, "
               f"{refreshed} refreshed), {evicted} evicted by TTL, "
               f"{len(merged_ips)} total in table, quota={quota}, {pf_msg}")
        record_run(True, len(merged_ips), quota, msg)

    else:
        # Replace mode (original, default). pf-table = today's top-N exactly.
        write_blocklist(fresh_ips)
        pf_msg = reload_pf_table()
        msg = f"replace mode: downloaded {len(fresh_ips)} IPs, quota={quota}, {pf_msg}"
        record_run(True, len(fresh_ips), quota, msg)

    log(msg)
    print(msg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
