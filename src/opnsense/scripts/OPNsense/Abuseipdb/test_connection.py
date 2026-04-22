#!/usr/bin/env python3
"""
Verify AbuseIPDB API key and connectivity.

Copyright (c) 2026 Kai Voss / IT-Service NF
BSD 2-Clause.
"""
import sys
from _common import get_config

try:
    import requests
except ImportError:
    print("requests library missing (py311-requests)")
    sys.exit(1)


def main() -> int:
    cfg = get_config()
    api_key = cfg["general"]["api_key"].strip()
    if not api_key:
        print("No API key configured.")
        return 1
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": "8.8.8.8"},
            timeout=10,
        )
    except Exception as exc:
        print(f"Request failed: {exc}")
        return 2

    if r.status_code == 200:
        print(f"OK — API reachable, key valid. Quota remaining: "
              f"{r.headers.get('X-RateLimit-Remaining', '?')}")
        return 0
    print(f"HTTP {r.status_code}: {r.text[:200]}")
    return 3


if __name__ == "__main__":
    sys.exit(main())
