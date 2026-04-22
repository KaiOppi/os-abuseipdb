# os-abuseipdb — OPNsense AbuseIPDB Integration

OPNsense-Plugin für bidirektionale Integration mit [AbuseIPDB](https://www.abuseipdb.com):

- **Blacklist-Download**: Aktuelle Angreifer-IPs aus der AbuseIPDB-Blacklist werden in eine pf-Table geladen und können per Firewall-Regel geblockt werden.
- **Reporter**: Lokale Firewall-Events an AbuseIPDB melden (bidirektionale Teilnahme am Threat-Intelligence-Netzwerk).
- **Dashboard-Widget**: Statistiken zu Blocks, Reports und API-Quota.
- **Fire & Forget**: Einmal konfiguriert, läuft das Plugin eigenständig per Cron.

## Status

In Entwicklung — Phase 1 (Grundgerüst).

## Features

- [x] Plugin-Grundgerüst
- [ ] Konfigurations-GUI (API-Key, Schwellenwerte, Schedule)
- [ ] Blacklist-Downloader → pf-Table
- [ ] Firewall-Alias-Integration
- [ ] Log-basierter Reporter → AbuseIPDB
- [ ] Dashboard-Widget
- [ ] Report-Log-Viewer

## Anforderungen

- OPNsense 26.1 oder neuer
- AbuseIPDB-Account mit API-Key (Free-Tier reicht für Einzelsysteme)

## Installation

Noch nicht verfügbar.

## Lizenz

BSD 2-Clause — siehe [LICENSE](LICENSE).

## Maintainer

IT-Service NF · Kai Voss · info@it-service-nf.de
