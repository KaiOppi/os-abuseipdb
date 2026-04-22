#!/usr/bin/env python3
"""
Shared helpers for os-abuseipdb scripts.

Copyright (c) 2026 Kai Schlestein
BSD 2-Clause.
"""
import json
import os
import sys
import xml.etree.ElementTree as ET
from typing import Optional

CONFIG_XML = "/conf/config.xml"
STATE_DIR = "/var/db/abuseipdb"
PF_TABLE = "os_abuseipdb"


def ensure_state_dir() -> None:
    os.makedirs(STATE_DIR, exist_ok=True)


def get_config() -> dict:
    """
    Read /conf/config.xml and return the Abuseipdb subtree as a nested dict.

    Returns defaults merged with live config — never raises on missing keys.
    """
    defaults = {
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
        },
    }

    if not os.path.exists(CONFIG_XML):
        return defaults

    try:
        tree = ET.parse(CONFIG_XML)
        root = tree.getroot()
        node = root.find("./OPNsense/Abuseipdb")
        if node is None:
            return defaults
        for section, fields in defaults.items():
            sec_node = node.find(section)
            if sec_node is None:
                continue
            for key in fields:
                val_node = sec_node.find(key)
                if val_node is not None and val_node.text is not None:
                    defaults[section][key] = val_node.text
    except Exception:
        # On parse error we return the defaults rather than crashing
        pass
    return defaults


def die(msg: str, code: int = 1) -> None:
    sys.stderr.write(msg.rstrip() + "\n")
    sys.exit(code)


def out_json(data: dict) -> None:
    sys.stdout.write(json.dumps(data))
    sys.stdout.flush()
