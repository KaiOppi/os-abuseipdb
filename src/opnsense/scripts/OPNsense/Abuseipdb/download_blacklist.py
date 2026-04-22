#!/usr/bin/env python3
"""
Download the AbuseIPDB blacklist into a pf table.

Copyright (c) 2026 Kai Schlestein
BSD 2-Clause.

Phase-1 stub: loads config, fetches blacklist (optional), writes table file.
The pfctl integration is finalised in phase 3.
"""
import os
import subprocess
import sys
from _common import PF_TABLE, STATE_DIR, die, ensure_state_dir, get_config

try:
    import requests
except ImportError:
    die("requests library missing (py311-requests)")


def fetch(api_key: str, confidence_min: int, limit: int) -> list[str]:
    r = requests.get(
        "https://api.abuseipdb.com/api/v2/blacklist",
        headers={"Key": api_key, "Accept": "text/plain"},
        params={"confidenceMinimum": confidence_min, "limit": limit},
        timeout=30,
    )
    r.raise_for_status()
    return [line.strip() for line in r.text.splitlines() if line.strip()]


def main() -> int:
    cfg = get_config()
    if cfg["general"]["enabled"] != "1" or cfg["blacklist"]["enabled"] != "1":
        print("Blacklist disabled — nothing to do.")
        return 0

    api_key = cfg["general"]["api_key"].strip()
    if not api_key:
        die("No API key configured.")

    conf_min = int(cfg["blacklist"]["confidence_min"])
    max_ips = int(cfg["blacklist"]["max_ips"])

    try:
        ips = fetch(api_key, conf_min, max_ips)
    except Exception as exc:
        die(f"Fetch failed: {exc}")

    ensure_state_dir()
    outfile = os.path.join(STATE_DIR, "blocklist.txt")
    with open(outfile, "w", encoding="ascii") as fh:
        fh.write("\n".join(ips) + "\n")

    # Load into pf table (replace). Table must exist (created via firewall alias in phase 3).
    try:
        subprocess.run(
            ["/sbin/pfctl", "-t", PF_TABLE, "-T", "replace", "-f", outfile],
            check=True, capture_output=True,
        )
    except subprocess.CalledProcessError as exc:
        # Not fatal in phase 1 — alias might not exist yet.
        print(f"pfctl load skipped: {exc.stderr.decode().strip()}")

    print(f"OK — {len(ips)} IPs written to {outfile}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
