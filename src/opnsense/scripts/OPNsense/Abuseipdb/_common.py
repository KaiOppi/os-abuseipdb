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

API_BASE = "https://api.abuseipdb.com/api/v2"


DEFAULT_CONFIG = {
    "general": {"enabled": "0", "api_key": ""},
    "blacklist": {
        "enabled": "0",
        "confidence_min": "90",
        "max_ips": "10000",
        "schedule": "0 3 * * *",
    },
    "reporter": {
        "enabled": "0",
        "min_hits": "3",
        "rate_limit_per_ip_min": "15",
        "daily_quota": "900",
        "default_categories": "14,15",
        "dry_run": "1",
        "precheck": "1",
        "precheck_min_confidence": "25",
    },
    "selfcare": {
        "enabled": "0",
        "ttl_hours": "72",
    },
}


def ensure_state_dir() -> None:
    os.makedirs(STATE_DIR, exist_ok=True)


def _column_exists(db, table: str, col: str) -> bool:
    row = db.execute(f"PRAGMA table_info({table})").fetchall()
    return any(r[1] == col for r in row)


def get_db() -> sqlite3.Connection:
    ensure_state_dir()
    db = sqlite3.connect(STATE_DB)
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
    # Schema migrations — additive only, never destructive.
    if not _column_exists(db, "reports", "iface"):
        db.execute("ALTER TABLE reports ADD COLUMN iface TEXT")
    if not _column_exists(db, "selfcare_entries", "iface"):
        db.execute("ALTER TABLE selfcare_entries ADD COLUMN iface TEXT")
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
