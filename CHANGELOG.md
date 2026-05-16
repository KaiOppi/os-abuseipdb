# Changelog

All notable changes to this project are documented here.
The format roughly follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project uses [Semantic Versioning](https://semver.org/).

## [0.6.1] — 2026-05-16

### Fixed
- **Hotfix on top of v0.6.0 — the firewall layer itself was still IPv4-only.** v0.6.0 made the reporter, the perma-block validator, the hit-counter sampler and the blacklist downloader family-aware, but `setup.php` was still creating the three pf-table aliases with `<proto>IPv4</proto>` and the three block rules with `<ipprotocol>inet</ipprotocol>`. Net effect: IPv6 addresses produced by the reporter or accepted by `permaban_add` would have been written to a v4-only alias (rejected by OPNsense's alias validation) and even if they had made it into the table the block rule would not match v6 traffic. Without this hotfix v0.6.0 was effectively cosmetic for the firewall path.

  Fix in `setup.php`:
  - All three aliases (`abuseipdb_blacklist`, `abuseipdb_selfcare`, `abuseipdb_permaban`) are now created with `proto="IPv4,IPv6"` (the `proto` field is a Multiple=Y OptionField, this is the canonical OPNsense way of saying "dual-family"). Upgrade-path: pre-v0.6.x installs are detected by a `proto !== "IPv4,IPv6"` check and silently promoted on the next setup run.
  - Both block-rule styles — Classic (`<filter><rule>`) and Automation (`OPNsense\Firewall\Filter`) — emit `ipprotocol="inet46"`. OPNsense expands that into two pf rules per directive (one `inet`, one `inet6`), verified with `pfctl -sr`.

  Verified on dev VM:
  ```
  block drop in log quick on vtnet0 inet  from <abuseipdb_selfcare> to any
  block drop in log quick on vtnet0 inet6 from <abuseipdb_selfcare> to any
  ```
  plus `pfctl -t abuseipdb_selfcare -T add 2001:db8::abcd` → "1/1 addresses added".

### Notes
- No schema change. The setup-script upgrade-path runs on every plugin save / configd-action, so existing installs pick it up automatically the next time they save the settings or hit a scheduled setup run.

## [0.6.0] — 2026-05-16

### Added
- **IPv6 support across the whole pipeline.** Until now the reporter dropped every IPv6 block event on the floor (the parser had an explicit `phase 5: IPv4 only` gate). With v0.6.0:
  - **Reporter** — `parse_line()` switches on the `ip_version` field of the filter-log entry and uses the correct column offsets for either IPv4 (`proto=parts[16], src=parts[18], dport=parts[21]`) or IPv6 (`proto=parts[12], src=parts[15], dport=parts[18]`). The OPNsense pf logger writes a different column layout for the two families, so a single offset set would have garbled v6 entries. The shared `is_private()` helper was already family-agnostic via `ipaddress.ip_address()`.
  - **Perma-Block** — the manual-add validator (`is_valid_ipv4`) became `is_valid_ip` and now accepts any canonical IPv4 or IPv6 address. Input is normalised through `ipaddress.ip_address()` so DB and pf agree on representation (`2001:0db8::1` → `2001:db8::1`). The PHP-side `ServiceController` validator dropped its `FILTER_FLAG_IPV4` flag and now accepts either family on the REST endpoints.
  - **Perma-Block hit-counter sampler** — the IP regex that parses `pfctl -T show -vv` output was extended to match both IPv4 and IPv6 table entries, so reboot-safe hit accounting works for both families.
  - **Blacklist downloader** — a new opt-in setting *Include IPv6 entries* on the Blacklist tab. The AbuseIPDB `/blacklist` endpoint defaults to IPv4-only (verified empirically 2026-05-16). When the checkbox is ticked the downloader issues a second explicit `ipVersion=6` call and merges both lists. Costs one extra blacklist quota slot per scheduled run. A v6 fetch failure (typically the daily 10-call blacklist limit) is soft: the v4 list is kept and the failure is logged. Default is off, so upgraded installs see no behavioural change.
  - **UI polish** — IP cells in the Self-Defense, Perma-Block and Reports tables are now `white-space: nowrap`, so 39-character v6 addresses no longer wrap mid-address.

### Notes
- Schema bump `Abuseipdb.xml`: `0.1.3 → 0.1.4`. New `blacklist.include_ipv6` BooleanField (default `0`). No data migration needed — existing configs read with the safe default.
- The pf tables (`abuseipdb_blacklist`, `abuseipdb_selfcare`, `abuseipdb_permaban`) are family-mixed by default in FreeBSD pf; no separate v4/v6 tables were introduced.
- Verified on the dev VM (192.168.3.161, VMID 150) against live filter-log lines from a dual-stack PPPoE WAN and against the AbuseIPDB blacklist endpoint with `ipVersion=6`.

## [0.5.0] — 2026-05-07

### Added
- **Configurable rule style.** New dropdown on the *General* tab — *Rule style* — choosing between three modes:
  - **Classic** (legacy `<filter><rule>` in `Firewall → Rules → WAN`) — the previous, hard-coded behaviour. Remains the default for upgraded installs that had no setting before.
  - **Automation** (modern `OPNsense\Firewall\Filter` model under `Firewall → Automation → Filter`) — the plugin's three block rules show up in the new Rules tab alongside hand-curated rules, sequenced at 1 so they fire first. Idempotent: matched by description marker, never duplicated.
  - **None** — plugin only maintains the three pf-table aliases (`abuseipdb_blacklist`, `abuseipdb_selfcare`, `abuseipdb_permaban`); the operator crafts their own block rules against those aliases. Preferred by users who keep tight ordering control over their rule list.
- **Manage block rules on save** checkbox. When unticked, the plugin removes its own rules on the next save and never touches firewall rules again — handy when an operator wants the plugin purely as a data feeder for the alias.
- **Automatic cleanup on style switch.** The plugin remembers the previously-applied style (`rules.last_applied_style`) and on every save removes its rules from that location before creating fresh ones in the newly-chosen style. No orphaned plugin rules, no duplicates.

  Triggered by community feedback (Constantin, GitHub issue) — power users who migrated their rule list to the new Automation/Filter tab were losing the rule order they curated, because the plugin kept dropping its block rules into the legacy WAN tab.

### Notes
- Schema bump `Abuseipdb.xml`: `0.1.2 → 0.1.3`. New `<rules>` group with `style` (default `classic`), `manage` (default `1`), `last_applied_style` (internal, plugin-managed). Pre-existing configs read with the defaults — no manual migration required.
- `setup.php` refactored: the rule lifecycle is factored out of three near-identical blocks into reusable helpers (`classic_apply`, `classic_remove`, `automation_apply`, `automation_remove`) routed by an `ensure_rule()` dispatcher.

## [0.4.2] — 2026-05-07

### Fixed
- **`setup.php` crashed on fresh OPNsense VPS installs.** Reported by a community tester on 26.1.7_3 amd64 — second external bug report. Root cause: a freshly-imaged OPNsense ships with an empty `<filter></filter>` element in `config.xml`. PHP's XML-to-array deserialiser turns that into the empty string `""`, **not** an empty array. The previous defensive check (`if (!isset($config["filter"]))`) only handled the missing-key case — when the key was present but a string, the next line's `$config["filter"]["rule"]` triggered PHP 8's `Cannot access offset of type string on string` TypeError, the script aborted, and the firewall block rule was never created.

  Fix: extended the defensive normalisation to `!isset(...) || !is_array(...)` for both `$config["filter"]` and `$config["filter"]["rule"]`. Also added a related guard for the single-existing-rule case where OPNsense's deserialiser collapses the rule list into one associative element — that variant is now wrapped in a list before the foreach.

  Workaround for users on 0.4.1 or earlier without the fix: add at least one dummy classic firewall rule via the GUI, then save AbuseIPDB settings. The presence of a real rule forces the parent `<filter>` element to be a non-empty array and side-steps the bug.

## [0.4.1] — 2026-05-06

### Added
- **Per-IP hit counter on the Perma-Block list.** Two new columns in the Perma-Block tab: **Hits** (cumulative total over reboots) and **Last hit** (timestamp of the last counter advance). The Hits cell additionally shows a small "seit Boot" line with the current pf-session counter.
- A new sampler script `permaban_count.py` runs from cron every 5 min, reads the in-memory pf-table counters (`pfctl -t abuseipdb_permaban -T show -vv`), computes the per-IP delta against the last sample, and folds it into the persistent total. Reboot-safe: if the kernel counter is lower than the last sample (zeroed by reboot or `pfctl -T zero`), the script treats the new value as the post-reboot delta. Resource cost is negligible — ~50 ms per run on a typical permaban table.
- New REST endpoint payload: `permaban_list` now returns `hits`, `current_session`, and `last_hit_ts` fields per row.
- New configd action: `abuseipdb permaban_count`.
- New cron job (auto-installed when permaban is enabled): "os-abuseipdb: perma-block hit counter sampler" — every 5 min.

### Migrations
- SQLite: three new columns on the existing `permaban` table — `cumulative_hits`, `pf_last_seen`, `last_hit_ts` — all additive with safe defaults of 0. Existing rows start at 0 hits and accrue from the first cron sample after upgrade.

## [0.4.0] — 2026-05-06

### Added
- **Perma-Block list — for IPs that just won't quit.** When the same attacker keeps reappearing in your Self-Defense list after each TTL expiry, you can now promote them to a permanent block. Two ways to land on the list:
  - **Auto-promote (default):** if an IP shows up in Self-Defense **3 times within 14 days** (configurable), it is moved to the Perma-Block table on the spot. The reporter checks inline as new selfcare entries are added, and a daily cron sweeps the history table for anything missed.
  - **Manual:** add an IP from the new "Perma-Block" tab, or click the new **→ Permaban** button on any row in the "Self-Defense" tab.
- **No AbuseIPDB report on promotion.** The decision to publicly flag an IP stays with the operator — Perma-Block is a local pf table only, populated independently of the reporter's submission flow.
- **Manual remove only.** Once an IP lands in Perma-Block, it stays there until you remove it from the GUI. The Self-Defense TTL doesn't apply.
- New pf table `abuseipdb_permaban`, alias of the same name, dedicated block rule installed at the top of the WAN ruleset (or floating, when multiple interfaces are selected).
- New Perma-Block configuration in `Firewall → AbuseIPDB → Perma-Block`: enabled, promote threshold (default 3), promote window in days (default 14).
- New stats counter `permaban_count` — visible in the info banner at the top of the plugin page.
- New REST endpoints:
  - `GET  /api/abuseipdb/service/permaban_list`
  - `POST /api/abuseipdb/service/permaban_add`     (body: `ip`, optional `note`)
  - `POST /api/abuseipdb/service/permaban_remove`  (body: `ip`)
  - `POST /api/abuseipdb/service/permaban_promote` (manual auto-promote scan)
- New configd actions: `abuseipdb permaban_list`, `abuseipdb permaban_add`, `abuseipdb permaban_remove`, `abuseipdb permaban_scan`.

### Migrations
- SQLite: two new tables, both additive — `selfcare_history (ip PK, first_seen_ts, last_seen_ts, occurrences)` keeps a counter of how often an IP cycled through Self-Defense; `permaban (ip PK, added_ts, source, note)` is the canonical Perma-Block ledger that re-syncs with pf on cron.

## [0.3.2] — 2026-04-30

### Fixed
- **`Firewall → AbuseIPDB` menu entry not visible after fresh install.** Reported by a community tester on OPNsense 26.1.6_2 — first external bug report 🎉. Root cause: our `+POST_INSTALL` only ran `service configd restart`, which has zero effect on the WebGUI's `MenuSystem` and `ACL` caches. The OPNsense core ships a helper for exactly this case (`/usr/local/etc/rc.configure_plugins POST_INSTALL` → `system_cache_flush()` → invalidates `MenuSystem`, `ACL` and `/var/lib/php/tmp/mdl_cache_*.json`). We now call it from both `+POST_INSTALL` and `+POST_DEINSTALL`, so the menu entry appears (and disappears on uninstall) immediately, without logout+login or a manual `configctl webgui restart`.

  Workaround for users still on 0.3.1 or earlier: add the AbuseIPDB dashboard widget (it has a config shortcut) or open `https://<your-opnsense>/ui/abuseipdb/` directly. Or: log out and back in.

## [0.3.1] — 2026-04-28

### Fixed
- **Reports table message column showed `&lt;` instead of `<`.** Pre-check skip messages like `SKIP: precheck confidence 0<25 (1 reports)` got HTML-entity-encoded twice in some browsers due to the `$('<div>').text(s).html()` round-trip we used for XSS escaping. Replaced with proper jQuery DOM construction (`$('<td>').text(...)`) so user-provided strings are inserted as plain text and never need HTML-entity encoding. Also applied to the Self-Defense "Currently blocked" table for the same reason.

## [0.3.0] — 2026-04-28

### Added
- **Per-interface tracking and statistics.** Reporter now reads the physical interface from each filter-log entry, maps it to the OPNsense identifier (`wan`, `opt1`, ...) and stores it alongside every report and self-defense entry. Multi-interface hits are stored as a comma-separated list (one IP can come in over several WANs in load-balance setups). Stable identifier is stored, not the friendly name — renaming the interface later doesn't invalidate historic data.
- **New "Statistics" tab** in the plugin GUI:
  - Self-defense currently active and total per interface
  - Reports today and total per interface
  - Reports per day for the last 14 days (CSS bar chart)
  - Self-defense additions per day for the last 14 days (CSS bar chart)
- **"Interface" column** in the Reports log table and the Self-Defense "Currently blocked" table. Friendly names are resolved to `descr` from `config.xml` at display time.
- Stats endpoint exposes `iface_descr` (identifier → friendly name map), `by_iface.{selfcare_active,selfcare_total,reports_today,reports_total}` and `daily.{reports,selfcare_added}` (14-day series).

### Migrations
- SQLite: added `iface` column to `reports` and `selfcare_entries` (additive, existing rows keep `NULL`).

## [0.2.4] — 2026-04-27

### Added
- **Self-defense counters in the Dashboard widget and the plugin info banner.** Both now show `active / total` for the self-defense block list. The widget gets a new "Self-defense (active/total)" row, and the info banner at the top of the plugin page does the same. Stats endpoint exposes two new fields: `selfcare_active` (live entries with non-expired TTL) and `selfcare_total` (everything ever added, incl. expired/removed).

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
