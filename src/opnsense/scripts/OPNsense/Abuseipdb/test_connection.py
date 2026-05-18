#!/usr/bin/env python3
"""
Verify AbuseIPDB API key and connectivity.

Copyright (c) 2026 Kai Schlestein
BSD 2-Clause.
"""
import sys
from _common import API_BASE, get_config, record_quota

try:
    import requests
except ImportError:
    print("requests library missing (install py311-requests)")
    sys.exit(1)


def main() -> int:
    cfg = get_config()
    api_key = cfg["general"]["api_key"].strip()
    if not api_key:
        print("No API key configured.")
        return 1
    try:
        r = requests.get(
            f"{API_BASE}/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": "8.8.8.8"},
            timeout=10,
        )
    except Exception as exc:
        print(f"Request failed: {exc}")
        return 2

    record_quota(None, "check", r)

    if r.status_code == 200:
        quota = r.headers.get("X-RateLimit-Remaining", "?")
        print(f"OK — API reachable, key valid. Quota remaining today: {quota}")
        return 0
    if r.status_code == 401:
        print("HTTP 401: API key rejected (check your key).")
        return 3
    if r.status_code == 429:
        print("HTTP 429: rate limited (quota exhausted for today).")
        return 4
    print(f"HTTP {r.status_code}: {r.text[:200]}")
    return 5


if __name__ == "__main__":
    sys.exit(main())
