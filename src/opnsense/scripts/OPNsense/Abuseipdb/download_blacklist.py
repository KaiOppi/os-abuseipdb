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

    log(f"starting blacklist fetch (confidence={conf_min}, limit={max_ips}, "
        f"include_ipv6={include_ipv6})")
    try:
        ips, quota = fetch_blacklist(api_key, conf_min, max_ips, include_ipv6)
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
