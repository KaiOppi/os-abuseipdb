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
    die, ensure_state_dir, get_config, get_db, log,
)

try:
    import requests
except ImportError:
    die("Python requests library missing (install py311-requests).")


def fetch_blacklist(api_key: str, confidence_min: int, limit: int) -> tuple[list[str], int | None]:
    """Return (ip_list, quota_remaining). Raises on non-2xx."""
    r = requests.get(
        f"{API_BASE}/blacklist",
        headers={"Key": api_key, "Accept": "text/plain"},
        params={"confidenceMinimum": confidence_min, "limit": limit},
        timeout=45,
    )
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")
    quota = r.headers.get("X-RateLimit-Remaining")
    try:
        quota_i = int(quota) if quota is not None else None
    except ValueError:
        quota_i = None
    ips = [line.strip() for line in r.text.splitlines() if line.strip()]
    return ips, quota_i


def write_blocklist(ips: list[str]) -> None:
    ensure_state_dir()
    tmp = BLOCKLIST_FILE + ".tmp"
    with open(tmp, "w", encoding="ascii") as fh:
        fh.write("\n".join(ips))
        if ips:
            fh.write("\n")
    os.replace(tmp, BLOCKLIST_FILE)


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

    log(f"starting blacklist fetch (confidence={conf_min}, limit={max_ips})")
    try:
        ips, quota = fetch_blacklist(api_key, conf_min, max_ips)
    except Exception as exc:
        record_run(False, 0, None, str(exc)[:200])
        die(f"fetch failed: {exc}")

    write_blocklist(ips)
    pf_msg = reload_pf_table()
    msg = f"downloaded {len(ips)} IPs, quota={quota}, {pf_msg}"
    log(msg)
    record_run(True, len(ips), quota, msg)
    print(msg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
