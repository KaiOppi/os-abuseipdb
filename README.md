# os-abuseipdb — OPNsense AbuseIPDB Integration

OPNsense-Plugin für bidirektionale Integration mit [AbuseIPDB](https://www.abuseipdb.com):

- **Blacklist** — lädt die AbuseIPDB-Blocklist in eine pf-Table und legt Firewall-Alias + WAN-Block-Regel automatisch an.
- **Reporter** — parst das OPNsense-Firewall-Log und meldet Angreifer-IPs an AbuseIPDB zurück (bidirektionale Teilnahme am Threat-Intelligence-Netzwerk).
- **Dashboard-Widget** — Live-Stats (Blocklist-Größe, letzter Download, Quota, Reports).
- **Fire & Forget** — Cron-Jobs werden beim Enablen automatisch angelegt (Download täglich, Reporter alle 5 Min).

## Installation

Download des `.pkg` aus dem [neuesten Release](https://github.com/KaiOppi/os-abuseipdb/releases/latest) und auf der OPNsense installieren:

```sh
pkg add https://github.com/KaiOppi/os-abuseipdb/releases/download/v0.1/os-abuseipdb-0.1.pkg
service configd restart
```

Dann in der WebGUI: **Firewall → AbuseIPDB** öffnen.

## Konfiguration

### Allgemein

1. Tab **General**
   - `Plugin enabled` aktivieren
   - `API Key` eintragen (80-stellig hex, Free-Tier bei [abuseipdb.com](https://www.abuseipdb.com/account/api))
2. **Save** — der Button **Test connection** prüft den Key sofort.

### Blacklist

Tab **Blacklist** → aktivieren.

Beim Save wird automatisch angelegt:
- Firewall-Alias `abuseipdb_blacklist` (Type: *External*)
- WAN-Block-Regel mit Source = diesem Alias, Log aktiv
- Cron-Job: täglicher Download um 03:13

Standard-Werte (konfigurierbar):
- `Minimum confidence score` — 90 (nur hochqualitative Einträge)
- `Maximum number of IPs` — 10000 (Free-Tier-Limit pro Call)

### Reporter

Tab **Reporter** → aktivieren.

Beim Save wird automatisch angelegt:
- Cron-Job: Reporter-Lauf alle 5 Min (parst `/var/log/filter/latest.log`)

Standard-Werte:
- `Minimum hits before report` — 3 (Dedupe gegen Rauschen)
- `Rate limit per IP (min)` — 15 (max. ein Report pro IP pro Zeitraum)
- `Daily report quota` — 900 (unter Free-Tier-Limit 1000)
- `Default categories` — `14,15` (PortScan + Hacking)

> **Hinweis:** IPs, die durch die Plugin-eigene Blacklist-Regel geblockt werden, werden **nicht** gemeldet (wäre Circular-Reporting).

## Dashboard-Widget

**Lobby → Dashboard → Add widget → "AbuseIPDB"** — zeigt Blocklist-Größe, letzter Download-Zeitpunkt, API-Quota, Reports-Count.

## Verifikation

```sh
# Blocklist in pf-Table
pfctl -t abuseipdb_blacklist -T show | wc -l

# Stats als JSON
configctl abuseipdb stats

# Manueller Download (verbraucht 1 API-Call)
configctl abuseipdb download

# Reporter manuell triggern
configctl abuseipdb report
```

## Deinstallation

```sh
pkg remove os-abuseipdb
```

- Firewall-Alias und Block-Regel **bleiben erhalten** (du kannst sie manuell löschen falls gewünscht).
- State-Verzeichnis `/var/db/abuseipdb/` bleibt erhalten (enthält Report-Historie in SQLite).

## Voraussetzungen

- OPNsense 26.1 oder neuer
- Python-Abhängigkeit `py311-requests` (wird per pkg-deps automatisch installiert)
- AbuseIPDB-API-Key (Free-Tier reicht für ein Einzelsystem)

## Status / Roadmap

- [x] Plugin-Grundgerüst + GUI
- [x] Blacklist-Downloader
- [x] Auto-Setup von Alias + Block-Rule
- [x] Reporter (Log → AbuseIPDB)
- [x] Cron-Integration (Download + Reporter)
- [x] Dashboard-Widget
- [x] Report-Log-Viewer im Plugin
- [x] FreeBSD-Paket + GitHub-Release
- [ ] Deutsche Übersetzung (vertagt auf Community-Crowdin-Workflow)
- [ ] Rule-zu-Kategorie-Mapping-UI (derzeit nur default-Kategorien)
- [ ] IPv6-Support (aktuell IPv4 only im Reporter)

## Lizenz

BSD 2-Clause — siehe [LICENSE](LICENSE).

## Maintainer

Kai Schlestein · info@it-service-nf.de
