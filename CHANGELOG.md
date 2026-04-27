# Changelog

All notable changes to this project are documented here.
The format roughly follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project uses [Semantic Versioning](https://semver.org/).

## [0.2.0] — 2026-04-24

First public beta. Feature-complete for the core use case (blacklist + reporter + self-defense) and stable on the two production systems it runs on. Looking for community testers.

### Highlights
- **Blacklist downloader** — pulls the AbuseIPDB blocklist into a pf table, auto-creates the firewall alias and block rule, daily cron at 03:13.
- **Reporter** — parses the OPNsense filter log, submits qualifying attacker IPs to AbuseIPDB every 5 min. Three legitimacy safeguards (dry-run default, pre-check against AbuseIPDB, noise filter).
- **Self-Defense** — local TTL-based block list. IPs that the reporter submits are also dropped into a second pf table and blocked locally until their TTL expires. Closes the window between "we saw the attack" and "AbuseIPDB community picks it up".
- **Dashboard widget** and in-plugin log viewer with quick-jump navigation.
- **Fire & forget** — every cron job is auto-created when you flip the corresponding enabled checkbox; no manual crontab editing.

### Known limitations
- IPv4 only (IPv6 reporter support is on the roadmap).
- No German translation yet — the plugin is in English pending OPNsense's community Crowdin workflow.

---

## [0.2.3] — 2026-04-27

### Changed
- **Self-defense fills based on pre-check, not just on successful report.** When pre-check is on (default) and an IP passes the confidence threshold, it is now added to the local block list immediately, regardless of whether the actual `/report` call to AbuseIPDB went through. This means the self-defense table keeps growing even when:
  - the daily report quota is exhausted (typical case for busy edges),
  - the reporter is still in dry-run mode (24 h validation window),
  - AbuseIPDB temporarily rejects a submit.

  Pre-check uses its own AbuseIPDB endpoint quota (1000 `/check`/day on the free tier, separate from `/report`), so confidence checks survive even after report quota is gone.

  When pre-check is **off**, behaviour is unchanged: self-defense only fills after a successful report.
- Reporter no longer aborts the loop when daily report quota is hit. It now keeps doing pre-checks for the remaining candidates so the self-defense table can still be fed.

## [0.2.2] — 2026-04-24

### Fixed
- **Cron jobs stayed enabled when the plugin was disabled, even with v0.2.1.** The `forceReload()` fix from v0.2.1 was right but not enough. The real bug: `write_config()` (used for the classic filter rule) internally rebuilds the SimpleXML tree from the legacy `$config` array and clobbers any model-tree changes we made earlier via `$mdl->serializeToConfig()`. The subsequent `Config::save()` then wrote the clobbered tree to disk, so cron flips were lost. Fix: re-serialize the alias and cron models *after* `write_config()`, right before the final `Config::save()`.

## [0.2.1] — 2026-04-24

### Fixed
- **Cron jobs stayed enabled when the plugin was disabled.** `setup.php` could see stale in-memory config when triggered right after `settings/set`, so `general.enabled` was still read as `1` while the user had already set it to `0`. Fix: `Config::getInstance()->forceReload()` before instantiating the model.

## 0.1.x — development iterations

These were the pre-public iterations. Kept for transparency.

| Version | Change |
|---|---|
| 0.1 | Initial pkg, 25 files |
| 0.1.1 | Locale cleanup; German language switch no longer broken |
| 0.1.2 | py-version-agnostic (post-install checks `import requests`) |
| 0.1.3 | OPNsense plugin annotations (`product_name`, etc.) |
| 0.1.4 | ACL/Menu format fix (no xml declaration, `page-firewall-abuseipdb`) |
| 0.1.5 | `disablereplyto=1` for pppoe WAN |
| 0.1.6 | Drop `<protocol>` field (`proto any` syntax error in pf) |
| 0.1.7 | Setup triggers ACL cache rebuild |
| 0.1.8 | Multi-interface block rule + log refresh |
| 0.1.9 | Quick-jump navigation |
| 0.1.10 | Navigation links open in same tab |
| 0.1.11 | Legitimacy safeguards (dry-run, pre-check, noise filter) |
| 0.1.12 | Delete+recreate rule on floating ↔ per-interface transitions |
| 0.1.13 | `block_interfaces` as TextField (multi-InterfaceField validation breaks) |
| 0.1.14 | Settings-save validation fix |
| 0.1.15 | setup.php maps friendly names (WAN, DSL) → internal IDs (wan, opt1) case-insensitively |
| 0.1.16 | Self-Defense tab: local TTL blocklist populated by the reporter |
| 0.1.17 | saveAll sends one POST instead of four (avoids stale-snapshot race) |
| 0.1.18 | Fix stacked tabs — `#frm_all` id on `.tab-content` itself |
| 0.1.19 | Move "Currently blocked" table into the Self-Defense tab |
