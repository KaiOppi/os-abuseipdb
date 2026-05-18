#!/usr/bin/env python3
"""
Shared helpers for os-abuseipdb scripts.

Copyright (c) 2026 Kai Schlestein
BSD 2-Clause.
"""
import json
import os
import sqlite3
import sys
import xml.etree.ElementTree as ET
from typing import Optional

CONFIG_XML = "/conf/config.xml"
STATE_DIR = "/var/db/abuseipdb"
STATE_DB = os.path.join(STATE_DIR, "state.sqlite")
BLOCKLIST_FILE = os.path.join(STATE_DIR, "blocklist.txt")
LOG_FILE = os.path.join(STATE_DIR, "abuseipdb.log")
PF_TABLE = "abuseipdb_blacklist"
PF_TABLE_SELFCARE = "abuseipdb_selfcare"
PF_TABLE_PERMABAN = "abuseipdb_permaban"

API_BASE = "https://api.abuseipdb.com/api/v2"


DEFAULT_CONFIG = {
    "general": {"enabled": "0", "api_key": ""},
    "blacklist": {
        "enabled": "0",
        "confidence_min": "90",
        "max_ips": "10000",
        "include_ipv6": "0",
        "persist_days": "0",
        "history_mode": "off",
        "history_size": "7",
        "history_threshold": "4",
        "schedule": "0 3 * * *",
    },
    "reporter": {
        "enabled": "0",
        "min_hits": "3",
        "rate_limit_per_ip_min": "15",
        "daily_quota": "900",
        "default_categories": "14,15",
        "comment_template": "Blocked by os-abuseipdb; {count} hits, proto={protos}, ports={ports}",
        "dry_run": "1",
        "precheck": "1",
        "precheck_min_confidence": "25",
    },
    "selfcare": {
        "enabled": "0",
        "ttl_hours": "72",
    },
    "permaban": {
        "enabled": "1",
        "promote_threshold": "3",
        "promote_window_days": "14",
    },
}


def ensure_state_dir() -> None:
    os.makedirs(STATE_DIR, exist_ok=True)


def _column_exists(db, table: str, col: str) -> bool:
    row = db.execute(f"PRAGMA table_info({table})").fetchall()
    return any(r[1] == col for r in row)


def get_db() -> sqlite3.Connection:
    ensure_state_dir()
    db = sqlite3.connect(STATE_DB, timeout=10)
    # WAL gives us readers-don't-block-writers semantics, which matters
    # because the reporter keeps a long-lived connection open during a
    # cycle while record_quota() opens its own short-lived writer per
    # API call. busy_timeout adds a graceful retry window for whichever
    # transaction lands second. Both PRAGMAs are persistent on the DB
    # file, but setting them on every connect is harmless.
    try:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA busy_timeout=5000")
    except sqlite3.OperationalError:
        pass
    db.execute("""
        CREATE TABLE IF NOT EXISTS blacklist_runs (
            ts INTEGER PRIMARY KEY,
            ok INTEGER NOT NULL,
            ip_count INTEGER NOT NULL,
            quota_remaining INTEGER,
            message TEXT
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            ts INTEGER NOT NULL,
            ip TEXT NOT NULL,
            categories TEXT,
            ok INTEGER NOT NULL,
            message TEXT,
            PRIMARY KEY (ts, ip)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS report_dedupe (
            ip TEXT PRIMARY KEY,
            last_reported_ts INTEGER NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS selfcare_entries (
            ip TEXT PRIMARY KEY,
            added_ts INTEGER NOT NULL,
            expires_ts INTEGER NOT NULL,
            source TEXT,
            categories TEXT,
            removed_ts INTEGER
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS selfcare_history (
            ip TEXT PRIMARY KEY,
            first_seen_ts INTEGER NOT NULL,
            last_seen_ts INTEGER NOT NULL,
            occurrences INTEGER NOT NULL DEFAULT 1
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS permaban (
            ip TEXT PRIMARY KEY,
            added_ts INTEGER NOT NULL,
            source TEXT,
            note TEXT
        )
    """)
    # v0.7.0: persistent blacklist — when blacklist.persist_days > 0 the
    # downloader keeps every IP it ever saw for up to N days, instead of
    # replacing the table each run with the current AbuseIPDB top-N. Catches
    # sleeper IPs that drop out of today's hot 10k but become active again
    # later (Constantin's wishlist).
    db.execute("""
        CREATE TABLE IF NOT EXISTS blacklist_persistent (
            ip TEXT PRIMARY KEY,
            first_seen_ts INTEGER NOT NULL,
            last_seen_ts INTEGER NOT NULL
        )
    """)
    # v0.8.0: snapshot-rotation blacklist. Each successful download becomes
    # its own immutable snapshot. The active pf-alias is computed from a
    # GROUP BY ... HAVING COUNT(*) >= threshold over the N most recent
    # snapshots. Lets the operator trade alias size for reputation quality
    # (intersection of last 7 days = ~1-2k constant offenders).
    db.execute("""
        CREATE TABLE IF NOT EXISTS blacklist_snapshots (
            snapshot_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            PRIMARY KEY (snapshot_id, ip)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS blacklist_snapshot_meta (
            snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
            fetched_ts INTEGER NOT NULL,
            ip_count INTEGER NOT NULL,
            quota_remaining INTEGER
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_snap_ip ON blacklist_snapshots (ip)")
    # v0.8.0: per-endpoint API quota history. Headers X-RateLimit-Remaining
    # and -Reset come back on every /report, /check, /blacklist call. We
    # log them all so the UI can show real-time-ish usage instead of
    # whatever the daily blacklist download last saw.
    db.execute("""
        CREATE TABLE IF NOT EXISTS api_quota_log (
            ts INTEGER NOT NULL,
            endpoint TEXT NOT NULL,
            remaining INTEGER,
            rate_limit INTEGER,
            reset_ts INTEGER,
            PRIMARY KEY (ts, endpoint)
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_quota_endpoint_ts ON api_quota_log (endpoint, ts DESC)")
    # Schema migrations — additive only, never destructive.
    if not _column_exists(db, "reports", "iface"):
        db.execute("ALTER TABLE reports ADD COLUMN iface TEXT")
    if not _column_exists(db, "selfcare_entries", "iface"):
        db.execute("ALTER TABLE selfcare_entries ADD COLUMN iface TEXT")
    # v0.4.1: per-IP hit counter for the perma-block list.
    # cumulative_hits  = total over all reboots (delta-tracked from pf)
    # pf_last_seen     = pf counter at last sampling — for delta computation
    # last_hit_ts      = unix-ts of the last sample where the counter advanced
    if not _column_exists(db, "permaban", "cumulative_hits"):
        db.execute("ALTER TABLE permaban ADD COLUMN cumulative_hits INTEGER NOT NULL DEFAULT 0")
    if not _column_exists(db, "permaban", "pf_last_seen"):
        db.execute("ALTER TABLE permaban ADD COLUMN pf_last_seen INTEGER NOT NULL DEFAULT 0")
    if not _column_exists(db, "permaban", "last_hit_ts"):
        db.execute("ALTER TABLE permaban ADD COLUMN last_hit_ts INTEGER NOT NULL DEFAULT 0")
    db.commit()
    return db


def get_iface_map() -> dict:
    """Build a phys-name → identifier map from /conf/config.xml. e.g.
    {"vtnet0": "wan", "igb1": "opt1"}. Used to resolve filter-log
    interface names to OPNsense identifiers."""
    out = {}
    if not os.path.exists(CONFIG_XML):
        return out
    try:
        root = ET.parse(CONFIG_XML).getroot()
        ifaces = root.find("./interfaces")
        if ifaces is None:
            return out
        for child in ifaces:
            ident = child.tag
            if_node = child.find("if")
            if if_node is not None and if_node.text:
                out[if_node.text.strip()] = ident
    except Exception:
        pass
    return out


def get_local_networks() -> list:
    """Return a list of `ipaddress.ip_network` objects for every directly
    connected subnet on this OPNsense — both IPv4 and IPv6. Used by the
    reporter to suppress reports of source IPs that belong to our own LAN.

    The IPv4 case was historically handled by the RFC1918 check inside
    is_private(); for IPv6 the LAN clients carry **globally routable** GUA
    addresses out of the WAN-delegated prefix (or a previous, still-cached
    prefix while the ISP rotates the PD), so the global-vs-private split
    no longer maps cleanly onto local-vs-remote."""
    import ipaddress
    import subprocess
    out = []
    try:
        r = subprocess.run(["/sbin/ifconfig"], capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            return out
        for line in r.stdout.splitlines():
            s = line.strip()
            if s.startswith("inet ") and not s.startswith("inet 127."):
                parts = s.split()
                ip = parts[1]
                try:
                    nm = parts[parts.index("netmask") + 1]
                except (ValueError, IndexError):
                    continue
                if nm.startswith("0x"):
                    try:
                        prefix = bin(int(nm, 16)).count("1")
                    except ValueError:
                        continue
                else:
                    try:
                        prefix = int(nm)
                    except ValueError:
                        continue
                try:
                    out.append(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
                except ValueError:
                    pass
            elif s.startswith("inet6 ") and "fe80::" not in s and not s.startswith("inet6 ::1"):
                parts = s.split()
                ip = parts[1].split("%")[0]
                try:
                    prefix = int(parts[parts.index("prefixlen") + 1])
                    out.append(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
                except (ValueError, IndexError):
                    pass
    except Exception:
        pass
    return out


def get_wan_iface_phys_names() -> set:
    """Return the set of physical interface names (e.g. {'pppoe0','vtnet0'})
    that look WAN-like in OPNsense: any of (a) a configured static IPv4
    or IPv6 gateway, (b) ipaddr/ipaddrv6 set to a dynamic family like
    pppoe, dhcp, slaac, track6, etc.

    Used by the reporter to ignore block events captured on LAN / OPT-LAN
    interfaces — block events on LAN are typically egress drops where the
    "source" is one of our own clients, not an attacker."""
    out = set()
    if not os.path.exists(CONFIG_XML):
        return out
    try:
        root = ET.parse(CONFIG_XML).getroot()
        ifaces = root.find("./interfaces")
        if ifaces is None:
            return out
        wan_like_dyn_v4 = {"dhcp", "pppoe", "ppp", "l2tp", "pptp"}
        wan_like_dyn_v6 = {"dhcp6", "slaac", "6rd", "6to4", "track6"}
        for child in ifaces:
            gw = child.find("gateway")
            gw6 = child.find("gatewayv6")
            ipa = child.find("ipaddr")
            ipa6 = child.find("ipaddrv6")
            v4 = ipa.text if ipa is not None else None
            v6 = ipa6.text if ipa6 is not None else None
            is_wan = (
                (gw is not None and (gw.text or "").strip()) or
                (gw6 is not None and (gw6.text or "").strip()) or
                v4 in wan_like_dyn_v4 or
                v6 in wan_like_dyn_v6
            )
            if not is_wan:
                continue
            if_node = child.find("if")
            if if_node is not None and if_node.text:
                out.add(if_node.text.strip())
    except Exception:
        pass
    return out


def get_iface_descr_map() -> dict:
    """identifier → friendly description (the 'descr' field in OPNsense
    interface settings, falling back to identifier-uppercase if unset)."""
    out = {}
    if not os.path.exists(CONFIG_XML):
        return out
    try:
        root = ET.parse(CONFIG_XML).getroot()
        ifaces = root.find("./interfaces")
        if ifaces is None:
            return out
        for child in ifaces:
            ident = child.tag
            descr = child.find("descr")
            out[ident] = (descr.text.strip() if descr is not None and descr.text
                          else ident.upper())
    except Exception:
        pass
    return out


def get_config() -> dict:
    """Read current plugin config from config.xml, merged with defaults."""
    cfg = {section: dict(values) for section, values in DEFAULT_CONFIG.items()}

    if not os.path.exists(CONFIG_XML):
        return cfg

    try:
        tree = ET.parse(CONFIG_XML)
        root = tree.getroot()
        node = root.find("./OPNsense/Abuseipdb")
        if node is None:
            return cfg
        for section, fields in cfg.items():
            sec_node = node.find(section)
            if sec_node is None:
                continue
            for key in fields:
                val_node = sec_node.find(key)
                if val_node is not None and val_node.text is not None:
                    cfg[section][key] = val_node.text
    except Exception:
        pass
    return cfg


def log(msg: str) -> None:
    ensure_state_dir()
    import time
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as fh:
        fh.write(f"{ts}  {msg}\n")


def die(msg: str, code: int = 1) -> None:
    log(f"ERROR: {msg}")
    sys.stderr.write(msg.rstrip() + "\n")
    sys.exit(code)


def out_json(data: dict) -> None:
    sys.stdout.write(json.dumps(data))
    sys.stdout.flush()


def record_quota(db, endpoint: str, response) -> None:
    # `db` may be None — record_quota then opens (and closes) its own
    # SQLite connection so module-level helpers like check_abuseipdb()
    # don't have to thread the handle through their call chain.
    """Persist X-RateLimit-* headers from a requests.Response so the UI
    can show fresh per-endpoint quota instead of the once-a-day blacklist
    snapshot. Silent on missing headers — AbuseIPDB sets them on every
    /report, /check, /blacklist response but a non-200 error path may
    skip them. Endpoint should be one of 'report', 'check', 'blacklist'."""
    import time as _time
    try:
        h = response.headers
    except AttributeError:
        return
    rem = h.get("X-RateLimit-Remaining")
    lim = h.get("X-RateLimit-Limit")
    rst = h.get("X-RateLimit-Reset")
    if rem is None and lim is None:
        return
    def _i(v):
        try:
            return int(v) if v is not None else None
        except (TypeError, ValueError):
            return None
    own_db = False
    if db is None:
        try:
            db = get_db()
            own_db = True
        except Exception:
            return
    try:
        try:
            db.execute(
                "INSERT OR REPLACE INTO api_quota_log "
                "(ts, endpoint, remaining, rate_limit, reset_ts) VALUES (?, ?, ?, ?, ?)",
                (int(_time.time()), endpoint, _i(rem), _i(lim), _i(rst)),
            )
            db.execute(
                "DELETE FROM api_quota_log WHERE ts < ?",
                (int(_time.time()) - 7 * 86400,),
            )
            db.commit()
        except Exception:
            # Quota persistence is best-effort — never let a transient
            # DB lock kill the surrounding /report or /check flow. The
            # next API call will retry the write soon enough.
            try:
                db.rollback()
            except Exception:
                pass
    finally:
        if own_db:
            try:
                db.close()
            except Exception:
                pass
