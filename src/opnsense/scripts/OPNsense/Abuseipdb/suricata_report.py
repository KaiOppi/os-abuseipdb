#!/usr/bin/env python3
"""
Parse the Suricata EVE JSON log and submit qualifying attacker source IPs
to AbuseIPDB (issue #7).

Copyright (c) 2026 Kai Schlestein
BSD 2-Clause.

This is a *second* reporting source next to reporter.py (which parses the
firewall block log). Both share the same submit-safety machinery and the
same daily quota / per-IP rate-limit / self-defense / permaban tables — the
suricata section only carries source-specific settings (log path, minimum
alert count, severity floor, category defaults, comment template).

Why Suricata alerts are legitimate AbuseIPDB material (and blacklist hits
are not — see the reporter): an IDS alert is our OWN first-hand detection of
malicious behaviour aimed at this host (port scan, web-app attack, exploit
attempt, brute force). That is exactly the evidence AbuseIPDB wants. We do
NOT report our own outbound traffic or LAN clients — the same WAN-inbound /
local-source filters the firewall reporter uses are applied here.

Flow per run:
 1. Read the tail of the EVE log since the last run (position file).
 2. Keep event_type == "alert" whose severity is at least as high as the
    configured floor.
 3. Attacker = src_ip, but only when src is public/external AND the
    destination is one of ours (private or a directly-connected subnet).
    That restricts us to inbound attacks against this box.
 4. Aggregate per attacker IP; map each alert's Suricata classtype to
    AbuseIPDB category IDs.
 5. Respect operator whitelist, per-IP rate limit and daily quota (shared
    with the firewall reporter), optional pre-check, dry-run.
 6. POST to /report; feed self-defense / permaban exactly like the reporter.
"""
import json
import os
import sys
import time
from collections import defaultdict

from _common import (get_config, get_db, get_iface_map, get_local_networks,
                     is_whitelisted, log, record_whitelist_skip)
# Reuse the firewall reporter's building blocks verbatim so both sources
# behave identically on the shared submit path (quota, dedupe, self-defense,
# permaban, pre-check). Importing reporter has no side effects beyond the
# requests-availability check it already performs.
from reporter import (check_abuseipdb, is_local_source, is_private,
                      maybe_promote, reports_today, selfcare_add,
                      should_skip_ip, submit_report)

try:
    import requests  # noqa: F401  (used transitively via reporter helpers)
except ImportError:
    from _common import die
    die("Python requests library missing (install py311-requests).")

POSITION_FILE_NAME = "suricata.pos"


# Suricata's `alert.category` is the classtype *description* string coming
# from classification.config, e.g. "Attempted Information Leak", "Web
# Application Attack", "A Network Trojan was detected". Map those (and a few
# common signature keywords) to AbuseIPDB category IDs. First match wins per
# alert; unmatched alerts fall back to the configured default_categories.
#
# AbuseIPDB categories used here:
#   4 DDoS  14 Port Scan  15 Hacking  16 SQL Injection  18 Brute-Force
#   20 Exploited Host  21 Web App Attack  22 SSH
CATEGORY_MAP = [
    ("port scan", "14"),
    ("network scan", "14"),
    ("attempted information leak", "14"),
    ("attempted-recon", "14"),
    ("detection of a network scan", "14"),
    ("sql injection", "16,21"),
    ("web application attack", "21"),
    ("web-application-attack", "21"),
    ("cross site", "21"),
    ("xss", "21"),
    ("brute", "18"),
    ("ssh", "22,18"),
    ("denial of service", "4"),
    ("ddos", "4"),
    ("attempted denial of service", "4"),
    ("trojan", "15,20"),
    ("malware", "15,20"),
    ("exploit", "15"),
    ("shellcode", "15"),
    ("attempted administrator privilege gain", "15"),
    ("attempted user privilege gain", "15"),
    ("privilege gain", "15"),
    ("successful administrator", "15,20"),
    ("misc attack", "15"),
    ("misc-attack", "15"),
    ("bad-unknown", "15"),
    ("potentially bad traffic", "15"),
    ("scan", "14"),
]


def map_categories(alert_category: str, signature: str) -> str | None:
    """Return a comma-separated AbuseIPDB category string for one alert, or
    None when nothing matches (caller then uses the configured default)."""
    hay = f"{alert_category or ''} {signature or ''}".lower()
    for keyword, cats in CATEGORY_MAP:
        if keyword in hay:
            return cats
    return None


def merge_categories(cat_sets: set, fallback: str) -> str:
    """Collapse a set of "a,b" category strings into one sorted, de-duped
    comma list. Falls back to `fallback` when nothing was mapped."""
    ids = set()
    for c in cat_sets:
        for part in c.split(","):
            part = part.strip()
            if part.isdigit():
                ids.add(int(part))
    if not ids:
        for part in fallback.split(","):
            part = part.strip()
            if part.isdigit():
                ids.add(int(part))
    return ",".join(str(i) for i in sorted(ids)) or "15"


def load_position(path: str) -> int:
    if os.path.exists(path):
        try:
            return int(open(path).read().strip())
        except Exception:
            return 0
    return 0


def save_position(path: str, pos: int) -> None:
    try:
        with open(path, "w") as fh:
            fh.write(str(pos))
    except Exception as exc:
        log(f"suricata: could not save position: {exc}")


def read_new_lines(eve_log: str, pos_file: str) -> list[str]:
    """Return EVE-log lines written since the last run, advancing the
    position file. Handles log rotation (file shrank → restart at 0)."""
    if not os.path.exists(eve_log):
        return []
    size = os.path.getsize(eve_log)
    pos = load_position(pos_file)
    if pos > size:
        pos = 0
    lines = []
    with open(eve_log, "r", encoding="utf-8", errors="replace") as fh:
        fh.seek(pos)
        for line in fh:
            lines.append(line)
        save_position(pos_file, fh.tell())
    return lines


def is_ours(ip_str: str, local_nets) -> bool:
    """True when the address is one of ours: RFC1918/loopback/etc. or an IP
    inside a directly-connected subnet (covers the public WAN IP and any
    IPv6 GUA LAN client out of the delegated prefix)."""
    return is_private(ip_str) or is_local_source(ip_str, local_nets)


def main() -> int:
    cfg = get_config()
    if cfg["general"]["enabled"] != "1":
        print("plugin disabled")
        return 0
    if cfg["suricata"]["enabled"] != "1":
        print("suricata reporter disabled")
        return 0

    api_key = cfg["general"]["api_key"].strip()
    if not api_key:
        from _common import die
        die("no api key configured")

    eve_log = (cfg["suricata"].get("eve_log", "") or "").strip() or "/var/log/suricata/eve.json"
    min_hits = max(1, int(cfg["suricata"]["min_hits"]))
    min_severity = max(1, min(3, int(cfg["suricata"]["min_severity"])))
    default_categories = cfg["suricata"]["default_categories"].strip() or "15"
    comment_template = (cfg["suricata"].get("comment_template", "") or "").strip()
    if not comment_template:
        comment_template = "Suricata IDS on OPNsense: {count} alert(s); {signatures}"

    # Submit-safety knobs are shared with the firewall reporter section.
    rate_min = int(cfg["reporter"]["rate_limit_per_ip_min"])
    daily_quota = int(cfg["reporter"]["daily_quota"])
    dry_run = cfg["reporter"]["dry_run"] == "1"
    precheck = cfg["reporter"]["precheck"] == "1"
    precheck_min_conf = int(cfg["reporter"]["precheck_min_confidence"])
    selfcare_on = cfg["selfcare"]["enabled"] == "1"
    selfcare_ttl = int(cfg["selfcare"]["ttl_hours"]) * 3600
    permaban_on = cfg["permaban"]["enabled"] == "1"
    permaban_threshold = max(2, int(cfg["permaban"]["promote_threshold"]))
    permaban_window = max(1, int(cfg["permaban"]["promote_window_days"])) * 86400

    from _common import STATE_DIR, ensure_state_dir
    ensure_state_dir()
    pos_file = os.path.join(STATE_DIR, POSITION_FILE_NAME)

    lines = read_new_lines(eve_log, pos_file)
    if not lines:
        print(f"no new eve lines ({eve_log})")
        return 0

    iface_map = get_iface_map()
    local_nets = get_local_networks()

    # Aggregate alerts per attacker IP.
    hits: dict[str, dict] = defaultdict(lambda: {
        "count": 0, "sigs": set(), "cats": set(), "ports": set(),
        "protos": set(), "ifaces": set(),
    })
    parsed_alerts = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except (ValueError, TypeError):
            continue
        if ev.get("event_type") != "alert":
            continue
        parsed_alerts += 1
        alert = ev.get("alert") or {}
        try:
            severity = int(alert.get("severity", 3))
        except (TypeError, ValueError):
            severity = 3
        # Keep only alerts at least as severe as the floor (1=high…3=low).
        if severity > min_severity:
            continue
        src_ip = ev.get("src_ip")
        dest_ip = ev.get("dest_ip")
        if not src_ip:
            continue
        # Attacker heuristic: src must be a public/external address and the
        # destination must be one of ours → inbound attack against this box.
        if is_private(src_ip) or is_local_source(src_ip, local_nets):
            continue
        if dest_ip and not is_ours(dest_ip, local_nets):
            # Both endpoints external — can't attribute an inbound attack,
            # skip (avoids reporting servers our clients merely talked to).
            continue

        sig = (alert.get("signature") or "").strip()
        category = (alert.get("category") or "").strip()
        proto = (ev.get("proto") or "").strip()
        dport = ev.get("dest_port")
        in_iface = (ev.get("in_iface") or "").strip()

        hits[src_ip]["count"] += 1
        if sig:
            hits[src_ip]["sigs"].add(sig)
        mapped = map_categories(category, sig)
        if mapped:
            hits[src_ip]["cats"].add(mapped)
        if dport is not None:
            hits[src_ip]["ports"].add(str(dport))
        if proto:
            hits[src_ip]["protos"].add(proto)
        ident = iface_map.get(in_iface, in_iface)
        if ident:
            hits[src_ip]["ifaces"].add(ident)

    if not hits:
        print(f"processed {len(lines)} lines / {parsed_alerts} alerts, no external attacker IPs")
        return 0

    db = get_db()
    sent = 0
    already_today = reports_today(db)
    print(f"suricata candidates: {len(hits)}, already reported today: {already_today}/{daily_quota}")

    for ip, info in sorted(hits.items(), key=lambda x: -x[1]["count"]):
        if info["count"] < min_hits:
            continue
        if should_skip_ip(db, ip, rate_min):
            continue
        if is_whitelisted(db, ip):
            record_whitelist_skip(db, ip, "suricata")
            log(f"whitelist skip {ip} (suricata)")
            continue

        categories = merge_categories(info["cats"], default_categories)
        sigs = "; ".join(sorted(info["sigs"]))[:300]
        ports = ",".join(sorted(info["ports"]))[:60]
        protos = ",".join(sorted(info["protos"]))[:30]
        ifaces_csv = ",".join(sorted(info["ifaces"]))[:60]
        ts = int(time.time())
        quota_full = (already_today + sent >= daily_quota)

        # Pre-check (shared /check quota, independent of /report quota).
        precheck_passed = False
        if precheck:
            conf, check_msg = check_abuseipdb(api_key, ip, db=db)
            if conf is None:
                db.execute(
                    "INSERT OR REPLACE INTO reports (ts, ip, categories, ok, message, iface, source) "
                    "VALUES (?, ?, ?, ?, ?, ?, 'suricata')",
                    (ts, ip, categories, 0, f"SKIP: precheck failed ({check_msg})"[:200], ifaces_csv),
                )
                continue
            if conf < precheck_min_conf:
                db.execute(
                    "INSERT OR REPLACE INTO reports (ts, ip, categories, ok, message, iface, source) "
                    "VALUES (?, ?, ?, ?, ?, ?, 'suricata')",
                    (ts, ip, categories, 0,
                     f"SKIP: precheck confidence {conf} below {precheck_min_conf} ({check_msg})"[:200], ifaces_csv),
                )
                continue
            precheck_passed = True

        # Self-defense as soon as pre-check confirms badness.
        if selfcare_on and precheck_passed:
            if selfcare_add(db, ip, ts, selfcare_ttl, categories, "suricata-precheck", ifaces_csv):
                log(f"selfcare add {ip} via {ifaces_csv} (suricata precheck)")
                if permaban_on:
                    maybe_promote(db, ip, ts, permaban_threshold, permaban_window)

        if quota_full:
            db.execute(
                "INSERT OR REPLACE INTO reports (ts, ip, categories, ok, message, iface, source) "
                "VALUES (?, ?, ?, ?, ?, ?, 'suricata')",
                (ts, ip, categories, 0, f"SKIP: daily quota {daily_quota} reached"[:200], ifaces_csv),
            )
            continue

        try:
            comment = comment_template.format(
                count=info["count"],
                signatures=sigs or "IDS alert",
                categories=categories,
                ports=ports,
                protos=protos,
                iface=ifaces_csv,
                src_ip=ip,
            )
        except (KeyError, IndexError, ValueError):
            comment = f"Suricata IDS on OPNsense: {info['count']} alert(s); {sigs or 'IDS alert'}"

        if dry_run:
            db.execute(
                "INSERT OR REPLACE INTO reports (ts, ip, categories, ok, message, iface, source) "
                "VALUES (?, ?, ?, ?, ?, ?, 'suricata')",
                (ts, ip, categories, 1,
                 f"DRY-RUN: would report ({info['count']} alerts: {sigs})"[:200], ifaces_csv),
            )
            sent += 1
            log(f"dry-run: would report {ip} ({info['count']} suricata alerts) via {ifaces_csv}")
            continue

        ok, msg, quota = submit_report(api_key, ip, categories, comment, db=db)
        db.execute(
            "INSERT OR REPLACE INTO reports (ts, ip, categories, ok, message, iface, source) "
            "VALUES (?, ?, ?, ?, ?, ?, 'suricata')",
            (ts, ip, categories, 1 if ok else 0, msg[:200], ifaces_csv),
        )
        if ok:
            db.execute(
                "INSERT OR REPLACE INTO report_dedupe (ip, last_reported_ts) VALUES (?, ?)",
                (ip, ts),
            )
            sent += 1
            log(f"reported {ip} ({info['count']} suricata alerts) via {ifaces_csv} -> {msg}")
            # Self-defense via the submit path when pre-check is OFF.
            if selfcare_on and not precheck:
                if selfcare_add(db, ip, ts, selfcare_ttl, categories, "suricata", ifaces_csv):
                    if permaban_on:
                        maybe_promote(db, ip, ts, permaban_threshold, permaban_window)
        else:
            log(f"suricata report {ip} failed: {msg}")
            if "rate limited" in msg or (quota is not None and quota == 0):
                db.commit()
                break

    db.commit()
    db.close()
    print(f"suricata reporter done: {sent} reports sent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
