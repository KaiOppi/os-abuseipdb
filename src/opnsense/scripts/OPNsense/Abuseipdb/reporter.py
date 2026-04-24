#!/usr/bin/env python3
"""
Parse the OPNsense filter log and submit qualifying source IPs to AbuseIPDB.

Copyright (c) 2026 Kai Schlestein
BSD 2-Clause.

Flow per run:
 1. Read the tail of /var/log/filter/latest.log since the last run.
 2. Extract block events with their rule label (uuid), source IP, protocol, dst port.
 3. Ignore IPs that were blocked by our OWN abuseipdb rule (no point reporting
    what we already pulled from their blacklist).
 4. Aggregate hits per source IP.
 5. Respect per-IP rate limit (default 15 min) and daily quota.
 6. POST to https://api.abuseipdb.com/api/v2/report with mapped categories.
"""
import ipaddress
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from _common import API_BASE, PF_TABLE_SELFCARE, STATE_DIR, die, ensure_state_dir, get_config, get_db, log

try:
    import requests
except ImportError:
    die("Python requests library missing (install py311-requests).")

FILTER_LOG = "/var/log/filter/latest.log"
POSITION_FILE = os.path.join(STATE_DIR, "reporter.pos")

# Our own rule must not trigger reports — it is the reaction to our pull,
# not an indicator of a fresh attack.
OUR_RULE_MARKER = "[os-abuseipdb]"

# Log line example after the RFC-5424 header:
# "0,,,02f4bab031b57d1e30553ce08e0ec131,vtnet0,match,block,in,4,0x0,,255,20794,0,DF,17,udp,458,192.168.3.14,224.0.0.251,5353,5353,438"
# We split on "] " after the [meta ...] marker, then comma-split.
META_SPLIT = re.compile(r"\[meta [^\]]*\]\s+")


def is_private(ip_str: str) -> bool:
    """True for any address that must never be reported (RFC1918, loopback,
    multicast, broadcast, CGN, link-local, reserved, unparseable)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (ip.is_private or ip.is_loopback or ip.is_link_local or
                ip.is_multicast or ip.is_reserved or ip.is_unspecified or
                str(ip) == "255.255.255.255")
    except ValueError:
        return True


def check_abuseipdb(api_key: str, ip: str) -> tuple[int | None, str]:
    """Ask AbuseIPDB what it knows about an IP. Returns (confidence, comment)."""
    try:
        r = requests.get(
            f"{API_BASE}/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        if r.status_code != 200:
            return None, f"check http {r.status_code}"
        data = r.json().get("data", {})
        conf = data.get("abuseConfidenceScore")
        return (int(conf) if conf is not None else 0,
                f"{data.get('totalReports', 0)} reports")
    except Exception as exc:
        return None, f"check failed: {exc}"


def parse_line(line: str):
    """Return (rule_label, action, src_ip, dst_port, proto) or None."""
    m = META_SPLIT.search(line)
    if not m:
        return None
    payload = line[m.end():].strip()
    parts = payload.split(",")
    if len(parts) < 20:
        return None
    try:
        rule_label = parts[3]
        action = parts[6]
        if action != "block":
            return None
        ip_version = parts[8]
        if ip_version != "4":
            return None  # phase 5: IPv4 only
        proto = parts[16]
        src_ip = parts[18]
        dst_port = parts[21] if len(parts) > 21 else ""
        return rule_label, action, src_ip, dst_port, proto
    except (IndexError, ValueError):
        return None


def get_rule_descr_by_label(label: str) -> str | None:
    """Look up a rule description from config.xml by its uuid/label."""
    import xml.etree.ElementTree as ET
    try:
        root = ET.parse("/conf/config.xml").getroot()
        # classic rules
        for r in root.findall("./filter/rule"):
            # classic rules have no uuid attribute, so can't match by label
            pass
        # modern OPNsense rules have uuid attributes
        for r in root.findall(".//Filter/rules/rule"):
            if r.get("uuid") == label:
                d = r.find("description")
                return d.text if d is not None else None
    except Exception:
        pass
    return None


def load_position() -> int:
    if os.path.exists(POSITION_FILE):
        try:
            return int(open(POSITION_FILE).read().strip())
        except Exception:
            return 0
    return 0


def save_position(pos: int) -> None:
    ensure_state_dir()
    with open(POSITION_FILE, "w") as fh:
        fh.write(str(pos))


def read_new_lines() -> list[str]:
    """Return log lines written since the last run."""
    if not os.path.exists(FILTER_LOG):
        return []
    size = os.path.getsize(FILTER_LOG)
    pos = load_position()
    # log rotation: if file shrank, start from 0
    if pos > size:
        pos = 0
    lines = []
    with open(FILTER_LOG, "r", encoding="utf-8", errors="replace") as fh:
        fh.seek(pos)
        for line in fh:
            lines.append(line)
        save_position(fh.tell())
    return lines


def reports_today(db) -> int:
    midnight = int(time.mktime(time.strptime(time.strftime("%Y-%m-%d 00:00:00"), "%Y-%m-%d %H:%M:%S")))
    row = db.execute("SELECT COUNT(*) FROM reports WHERE ts >= ? AND ok = 1", (midnight,)).fetchone()
    return row[0] if row else 0


def should_skip_ip(db, ip: str, rate_limit_min: int) -> bool:
    row = db.execute("SELECT last_reported_ts FROM report_dedupe WHERE ip = ?", (ip,)).fetchone()
    if row is None:
        return False
    return (time.time() - row[0]) < rate_limit_min * 60


def submit_report(api_key: str, ip: str, categories: str, comment: str) -> tuple[bool, str, int | None]:
    try:
        r = requests.post(
            f"{API_BASE}/report",
            headers={"Key": api_key, "Accept": "application/json"},
            data={"ip": ip, "categories": categories, "comment": comment[:1000]},
            timeout=10,
        )
    except Exception as exc:
        return False, f"request failed: {exc}", None
    quota = r.headers.get("X-RateLimit-Remaining")
    try:
        quota_i = int(quota) if quota is not None else None
    except ValueError:
        quota_i = None
    if r.status_code == 200:
        return True, "ok", quota_i
    if r.status_code == 429:
        return False, "rate limited", quota_i
    return False, f"http {r.status_code}: {r.text[:100]}", quota_i


def main() -> int:
    cfg = get_config()
    if cfg["general"]["enabled"] != "1":
        print("plugin disabled")
        return 0
    if cfg["reporter"]["enabled"] != "1":
        print("reporter disabled")
        return 0

    api_key = cfg["general"]["api_key"].strip()
    if not api_key:
        die("no api key configured")

    min_hits = int(cfg["reporter"]["min_hits"])
    rate_min = int(cfg["reporter"]["rate_limit_per_ip_min"])
    daily_quota = int(cfg["reporter"]["daily_quota"])
    default_categories = cfg["reporter"]["default_categories"].strip() or "14,15"
    dry_run = cfg["reporter"]["dry_run"] == "1"
    precheck = cfg["reporter"]["precheck"] == "1"
    precheck_min_conf = int(cfg["reporter"]["precheck_min_confidence"])
    selfcare_on = cfg["selfcare"]["enabled"] == "1"
    selfcare_ttl = int(cfg["selfcare"]["ttl_hours"]) * 3600

    lines = read_new_lines()
    if not lines:
        print("no new log lines")
        return 0

    # Aggregate hits per IP
    hits: dict[str, dict] = defaultdict(lambda: {"count": 0, "labels": set(), "ports": set(), "protos": set()})
    for line in lines:
        parsed = parse_line(line)
        if not parsed:
            continue
        rule_label, action, src_ip, dst_port, proto = parsed
        if is_private(src_ip):
            continue
        # Skip hits from our own rule
        descr = get_rule_descr_by_label(rule_label) or ""
        if OUR_RULE_MARKER in descr:
            continue
        hits[src_ip]["count"] += 1
        hits[src_ip]["labels"].add(rule_label)
        if dst_port:
            hits[src_ip]["ports"].add(dst_port)
        if proto:
            hits[src_ip]["protos"].add(proto)

    if not hits:
        print(f"processed {len(lines)} log lines, no public-IP block hits")
        return 0

    db = get_db()
    sent = 0
    already_today = reports_today(db)
    print(f"hit candidates: {len(hits)}, already reported today: {already_today}/{daily_quota}")

    for ip, info in sorted(hits.items(), key=lambda x: -x[1]["count"]):
        if info["count"] < min_hits:
            continue
        if already_today + sent >= daily_quota:
            print("daily quota reached, stopping")
            break
        if should_skip_ip(db, ip, rate_min):
            continue

        ports = ",".join(sorted(info["ports"]))[:60]
        protos = ",".join(sorted(info["protos"]))[:30]
        ts = int(time.time())

        # Optional: pre-check against AbuseIPDB. Skip if nobody else flagged it yet.
        if precheck:
            conf, check_msg = check_abuseipdb(api_key, ip)
            if conf is None:
                # API error — don't skip silently, but don't report either
                db.execute(
                    "INSERT OR REPLACE INTO reports (ts, ip, categories, ok, message) VALUES (?, ?, ?, ?, ?)",
                    (ts, ip, default_categories, 0, f"SKIP: precheck failed ({check_msg})"[:200]),
                )
                continue
            if conf < precheck_min_conf:
                db.execute(
                    "INSERT OR REPLACE INTO reports (ts, ip, categories, ok, message) VALUES (?, ?, ?, ?, ?)",
                    (ts, ip, default_categories, 0, f"SKIP: precheck confidence {conf}<{precheck_min_conf} ({check_msg})"[:200]),
                )
                continue

        comment = f"Blocked by OPNsense firewall; {info['count']} hits, proto={protos}, ports={ports}"

        if dry_run:
            db.execute(
                "INSERT OR REPLACE INTO reports (ts, ip, categories, ok, message) VALUES (?, ?, ?, ?, ?)",
                (ts, ip, default_categories, 1, f"DRY-RUN: would report ({info['count']} hits)"[:200]),
            )
            sent += 1
            log(f"dry-run: would report {ip} ({info['count']} hits)")
            continue

        ok, msg, quota = submit_report(api_key, ip, default_categories, comment)
        db.execute(
            "INSERT OR REPLACE INTO reports (ts, ip, categories, ok, message) VALUES (?, ?, ?, ?, ?)",
            (ts, ip, default_categories, 1 if ok else 0, msg[:200]),
        )
        if ok:
            db.execute(
                "INSERT OR REPLACE INTO report_dedupe (ip, last_reported_ts) VALUES (?, ?)",
                (ip, ts),
            )
            sent += 1
            log(f"reported {ip} ({info['count']} hits) -> {msg}")

            # Self-defense: also drop this IP into our local pf table so it
            # stops hitting us while AbuseIPDB catches up. ttl_hours-driven,
            # cleanup cron removes expired entries. Keep existing expiry if
            # the IP is already tracked (don't extend silently).
            if selfcare_on:
                existing = db.execute(
                    "SELECT expires_ts FROM selfcare_entries WHERE ip = ? AND removed_ts IS NULL",
                    (ip,),
                ).fetchone()
                if existing is None:
                    expires = ts + selfcare_ttl
                    db.execute(
                        "INSERT OR REPLACE INTO selfcare_entries "
                        "(ip, added_ts, expires_ts, source, categories, removed_ts) "
                        "VALUES (?, ?, ?, ?, ?, NULL)",
                        (ip, ts, expires, "reporter", default_categories),
                    )
                    try:
                        subprocess.run(
                            ["/sbin/pfctl", "-t", PF_TABLE_SELFCARE, "-T", "add", ip],
                            check=False, capture_output=True, timeout=5,
                        )
                    except Exception as exc:
                        log(f"selfcare pfctl add {ip} failed: {exc}")
        else:
            log(f"report {ip} failed: {msg}")
            if "rate limited" in msg or (quota is not None and quota == 0):
                db.commit()
                break
    db.commit()
    db.close()
    print(f"reporter done: {sent} reports sent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
