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
from _common import (API_BASE, PF_TABLE_PERMABAN, PF_TABLE_SELFCARE,
                     STATE_DIR, die, ensure_state_dir, get_config, get_db,
                     get_iface_map, get_local_networks,
                     get_wan_iface_phys_names, log)

try:
    import requests
except ImportError:
    die("Python requests library missing (install py311-requests).")

FILTER_LOG = "/var/log/filter/latest.log"
POSITION_FILE = os.path.join(STATE_DIR, "reporter.pos")

# Our own rule must not trigger reports — it is the reaction to our pull,
# not an indicator of a fresh attack.
OUR_RULE_MARKER = "[os-abuseipdb]"

# Log line examples after the RFC-5424 header. The pf log uses different
# column layouts for IPv4 and IPv6 — the field positions for proto/src/dst/ports
# do not line up, so parse_line() switches on parts[8] (ip_version).
#
# IPv4 (rulenr=0 ... 4=ip_ver ... 15=proto_num,16=proto_name,17=len,18=src,19=dst,20=sport,21=dport):
#   "0,,,<uuid>,vtnet0,match,block,in,4,0x0,,255,20794,0,DF,17,udp,458,192.168.3.14,224.0.0.251,5353,5353,438"
#
# IPv6 (rulenr=19 ... 6=ip_ver ... 12=proto_name,13=proto_num,14=len,15=src,16=dst,17=sport,18=dport):
#   "19,,,<uuid>,pppoe0,match,block,in,6,0x00,0x86c31,113,tcp,6,20,2603:10a0:31c:81c1:0:1:8b:757a,2a11:fb80::1,443,49408,0,..."
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
    """Return (rule_label, action, src_ip, dst_port, proto, ifname) or None.
    ifname is the physical interface name from the log (e.g. 'vtnet0', 'igb1').
    Handles both IPv4 and IPv6 block events (column layouts differ).
    Only inbound block events (parts[7] == 'in') are returned — outbound
    drops are local-egress events whose 'source' is one of our own clients
    and must never reach the AbuseIPDB submit path."""
    m = META_SPLIT.search(line)
    if not m:
        return None
    payload = line[m.end():].strip()
    parts = payload.split(",")
    if len(parts) < 18:
        return None
    try:
        rule_label = parts[3]
        ifname = parts[4]
        action = parts[6]
        direction = parts[7]
        if action != "block" or direction != "in":
            return None
        ip_version = parts[8]
        if ip_version == "4":
            proto = parts[16]
            src_ip = parts[18]
            dst_port = parts[21] if len(parts) > 21 else ""
        elif ip_version == "6":
            proto = parts[12]
            src_ip = parts[15]
            dst_port = parts[18] if len(parts) > 18 else ""
        else:
            return None
        return rule_label, action, src_ip, dst_port, proto, ifname
    except (IndexError, ValueError):
        return None


def is_local_source(ip_str: str, local_nets) -> bool:
    """True if the address lives in a directly-connected subnet on this
    OPNsense. This is the v6 equivalent of the RFC1918 check inside
    is_private(): for IPv4 LAN clients the source is private by definition,
    but for IPv6 the LAN clients hold global addresses out of the WAN-
    delegated prefix (or a stale earlier prefix while the ISP rotates).
    We check the actual interface networks to catch those."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for net in local_nets:
        if ip.version == net.version and ip in net:
            return True
    return False


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


def is_permabanned(db, ip: str) -> bool:
    return db.execute("SELECT 1 FROM permaban WHERE ip = ?", (ip,)).fetchone() is not None


def history_upsert(db, ip: str, ts: int) -> int:
    """Increment selfcare_history for an IP and return its new occurrence count.
    Each call counts as one fresh selfcare hit (the caller decides when to call,
    typically only on new selfcare additions, not on every reporter run)."""
    row = db.execute(
        "SELECT first_seen_ts, occurrences FROM selfcare_history WHERE ip = ?",
        (ip,),
    ).fetchone()
    if row is None:
        db.execute(
            "INSERT INTO selfcare_history (ip, first_seen_ts, last_seen_ts, occurrences) "
            "VALUES (?, ?, ?, 1)",
            (ip, ts, ts),
        )
        return 1
    new_count = row[1] + 1
    db.execute(
        "UPDATE selfcare_history SET last_seen_ts = ?, occurrences = ? WHERE ip = ?",
        (ts, new_count, ip),
    )
    return new_count


def maybe_promote(db, ip: str, ts: int, threshold: int, window_sec: int) -> bool:
    """Promote IP to permaban if it has hit the threshold inside the window.
    Returns True when promotion happened in this call."""
    row = db.execute(
        "SELECT occurrences, first_seen_ts, last_seen_ts FROM selfcare_history WHERE ip = ?",
        (ip,),
    ).fetchone()
    if row is None:
        return False
    occ, first_ts, last_ts = row
    if occ < threshold:
        return False
    # Window check: at least `threshold` events were observed inside the window.
    # Approximation: if first_seen_ts is older than window we still allow it
    # because the most recent event must be inside the window for the
    # selfcare_add path that triggered this check. We require last_seen-first_seen
    # not exceed window + slack? Simpler & user-friendly: trigger when
    # occurrences crossed threshold AND last_seen is recent (within window).
    if (ts - last_ts) > window_sec:
        return False
    first_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(first_ts))
    last_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(last_ts))
    db.execute(
        "INSERT OR REPLACE INTO permaban (ip, added_ts, source, note) "
        "VALUES (?, ?, ?, ?)",
        (ip, ts, "auto-promote",
         f"{occ} selfcare hits between {first_str} and {last_str}"),
    )
    try:
        subprocess.run(
            ["/sbin/pfctl", "-t", PF_TABLE_PERMABAN, "-T", "add", ip],
            check=False, capture_output=True, timeout=5,
        )
    except Exception as exc:
        log(f"permaban pfctl add {ip} failed: {exc}")
    log(f"permaban auto-promote {ip} ({occ} hits)")
    return True


def selfcare_add(db, ip: str, ts: int, ttl_sec: int, categories: str, source: str, iface: str = "") -> bool:
    """Insert IP into selfcare_entries + pf table. Return True if newly added,
    False if already tracked (existing TTL preserved, no silent extension).
    Also bumps selfcare_history occurrence count on each newly-added entry."""
    if is_permabanned(db, ip):
        return False
    existing = db.execute(
        "SELECT expires_ts FROM selfcare_entries WHERE ip = ? AND removed_ts IS NULL",
        (ip,),
    ).fetchone()
    if existing is not None:
        return False
    expires = ts + ttl_sec
    db.execute(
        "INSERT OR REPLACE INTO selfcare_entries "
        "(ip, added_ts, expires_ts, source, categories, iface, removed_ts) "
        "VALUES (?, ?, ?, ?, ?, ?, NULL)",
        (ip, ts, expires, source, categories, iface),
    )
    try:
        subprocess.run(
            ["/sbin/pfctl", "-t", PF_TABLE_SELFCARE, "-T", "add", ip],
            check=False, capture_output=True, timeout=5,
        )
    except Exception as exc:
        log(f"selfcare pfctl add {ip} failed: {exc}")
    history_upsert(db, ip, ts)
    return True


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
    comment_template = (cfg["reporter"].get("comment_template", "") or "").strip()
    if not comment_template:
        comment_template = ("Blocked by os-abuseipdb; {count} hits, "
                            "proto={protos}, ports={ports}")
    dry_run = cfg["reporter"]["dry_run"] == "1"
    precheck = cfg["reporter"]["precheck"] == "1"
    precheck_min_conf = int(cfg["reporter"]["precheck_min_confidence"])
    selfcare_on = cfg["selfcare"]["enabled"] == "1"
    selfcare_ttl = int(cfg["selfcare"]["ttl_hours"]) * 3600
    permaban_on = cfg["permaban"]["enabled"] == "1"
    permaban_threshold = max(2, int(cfg["permaban"]["promote_threshold"]))
    permaban_window = max(1, int(cfg["permaban"]["promote_window_days"])) * 86400

    lines = read_new_lines()
    if not lines:
        print("no new log lines")
        return 0

    # Build phys-name → identifier map once (e.g. "vtnet0" → "wan", "igb1" → "opt1").
    # We store the identifier (stable, never changes) — friendly description is
    # resolved at display time so renaming an interface doesn't invalidate
    # historic data.
    iface_map = get_iface_map()
    # WAN-like physical interfaces (with a configured gateway or dynamic
    # ipaddr/ipaddrv6). Block events on anything outside this set are
    # egress drops on a LAN/OPT-LAN interface — never AbuseIPDB material.
    wan_phys = get_wan_iface_phys_names()
    # Directly-connected subnets (v4 + v6) — used to catch LAN clients
    # whose source IP is globally routable (IPv6 SLAAC out of a delegated
    # prefix, or a stale prefix while the ISP rotates).
    local_nets = get_local_networks()

    # Aggregate hits per IP
    hits: dict[str, dict] = defaultdict(lambda: {"count": 0, "labels": set(), "ports": set(), "protos": set(), "ifaces": set()})
    for line in lines:
        parsed = parse_line(line)
        if not parsed:
            continue
        rule_label, action, src_ip, dst_port, proto, ifname = parsed
        # Defence layer 1: only count events on WAN-like interfaces.
        # If wan_phys is empty (config read failed) we fall through to
        # the per-IP defences below rather than silently dropping every
        # event.
        if wan_phys and ifname not in wan_phys:
            continue
        if is_private(src_ip):
            continue
        # Defence layer 2: drop sources that live in any directly-connected
        # subnet on this box (covers IPv6 GUA LAN clients).
        if is_local_source(src_ip, local_nets):
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
        # Map physical interface to OPNsense identifier; unknown phys names
        # are stored as-is so the user can still see something useful.
        ident = iface_map.get(ifname, ifname)
        if ident:
            hits[src_ip]["ifaces"].add(ident)

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
        if should_skip_ip(db, ip, rate_min):
            continue

        ports = ",".join(sorted(info["ports"]))[:60]
        protos = ",".join(sorted(info["protos"]))[:30]
        ifaces_csv = ",".join(sorted(info["ifaces"]))[:60]
        ts = int(time.time())
        quota_full = (already_today + sent >= daily_quota)

        # Pre-check (independent quota at AbuseIPDB: /check separate from /report).
        # Even when daily report quota is exhausted, we keep doing pre-checks so
        # that confirmed-bad IPs can still feed the local self-defense table.
        precheck_passed = False
        if precheck:
            conf, check_msg = check_abuseipdb(api_key, ip)
            if conf is None:
                db.execute(
                    "INSERT OR REPLACE INTO reports (ts, ip, categories, ok, message, iface) VALUES (?, ?, ?, ?, ?, ?)",
                    (ts, ip, default_categories, 0, f"SKIP: precheck failed ({check_msg})"[:200], ifaces_csv),
                )
                continue
            if conf < precheck_min_conf:
                db.execute(
                    "INSERT OR REPLACE INTO reports (ts, ip, categories, ok, message, iface) VALUES (?, ?, ?, ?, ?, ?)",
                    (ts, ip, default_categories, 0, f"SKIP: precheck confidence {conf} below {precheck_min_conf} ({check_msg})"[:200], ifaces_csv),
                )
                continue
            precheck_passed = True

        # Self-defense add as soon as pre-check confirms badness — does not
        # depend on whether we still have report quota or are in dry-run.
        # When pre-check is off we keep the old behaviour (add only after a
        # successful report) since we have no confidence signal here.
        if selfcare_on and precheck_passed:
            if selfcare_add(db, ip, ts, selfcare_ttl, default_categories, "precheck", ifaces_csv):
                log(f"selfcare add {ip} via {ifaces_csv} (precheck conf>={precheck_min_conf})")
                if permaban_on:
                    maybe_promote(db, ip, ts, permaban_threshold, permaban_window)

        # Submit path — skip when daily quota is exhausted.
        if quota_full:
            db.execute(
                "INSERT OR REPLACE INTO reports (ts, ip, categories, ok, message, iface) VALUES (?, ?, ?, ?, ?, ?)",
                (ts, ip, default_categories, 0, f"SKIP: daily quota {daily_quota} reached"[:200], ifaces_csv),
            )
            continue

        try:
            comment = comment_template.format(
                count=info["count"],
                protos=protos,
                ports=ports,
                iface=ifaces_csv,
                src_ip=ip,
            )
        except (KeyError, IndexError, ValueError):
            # Bad template — fall back to the built-in form so the run is
            # never blocked by a typo in the settings field.
            comment = (f"Blocked by os-abuseipdb; {info['count']} hits, "
                       f"proto={protos}, ports={ports}")

        if dry_run:
            db.execute(
                "INSERT OR REPLACE INTO reports (ts, ip, categories, ok, message, iface) VALUES (?, ?, ?, ?, ?, ?)",
                (ts, ip, default_categories, 1, f"DRY-RUN: would report ({info['count']} hits)"[:200], ifaces_csv),
            )
            sent += 1
            log(f"dry-run: would report {ip} ({info['count']} hits) via {ifaces_csv}")
            continue

        ok, msg, quota = submit_report(api_key, ip, default_categories, comment)
        db.execute(
            "INSERT OR REPLACE INTO reports (ts, ip, categories, ok, message, iface) VALUES (?, ?, ?, ?, ?, ?)",
            (ts, ip, default_categories, 1 if ok else 0, msg[:200], ifaces_csv),
        )
        if ok:
            db.execute(
                "INSERT OR REPLACE INTO report_dedupe (ip, last_reported_ts) VALUES (?, ?)",
                (ip, ts),
            )
            sent += 1
            log(f"reported {ip} ({info['count']} hits) via {ifaces_csv} -> {msg}")

            # Selfcare add via reporter path — only when pre-check is OFF
            # (otherwise the precheck path above already added it).
            if selfcare_on and not precheck:
                if selfcare_add(db, ip, ts, selfcare_ttl, default_categories, "reporter", ifaces_csv):
                    if permaban_on:
                        maybe_promote(db, ip, ts, permaban_threshold, permaban_window)
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
