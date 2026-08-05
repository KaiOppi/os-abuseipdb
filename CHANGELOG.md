# Changelog

All notable changes to this project are documented here.
The format roughly follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project uses [Semantic Versioning](https://semver.org/).

## [0.13.0] — 2026-08-05

### Added
- **Subnet / prefix aggregation for local defense ([#8](https://github.com/KaiOppi/os-abuseipdb/issues/8)).** IPv6 attacks arrive in waves from the same prefix — an attacker holding a /64 just rotates through addresses, so blocking individual /128s is whack-a-mole. A new **Aggregation** tab lets the plugin block the whole prefix locally once a wave is detected:
  - When **N** distinct addresses (default 5) from the same prefix land in self-defense within the counting window (default 24 h), the whole prefix is blocked — **/64** for IPv6, **/24** for IPv4 (both configurable).
  - The prefix block uses the normal self-defense TTL, so it lifts automatically like a per-IP entry.
  - Each further wave (fresh addresses after the previous aggregation) bumps the prefix's wave counter; after **`permaban_after`** waves (default 2) the whole prefix is promoted to the perma-block list. Set to 0 to keep prefixes on self-defense TTL only.
  - **Reporting to AbuseIPDB stays strictly per-IP** — the `/report` API takes no CIDR, and each rotated address is genuine independent evidence. This feature only affects the local pf tables.
  - **Whitelist-safe:** a prefix that would swallow any operator-whitelisted IP is never blocked. Opt-in, and requires Self-Defense to be enabled. Aggregated prefixes appear as CIDR rows (source `aggregate` / `aggregate-prefix`) in the Self-Defense and Perma-Block lists.
  - Runs on its own 10-minute cron when enabled. Thresholds/defaults informed by real-world DMZ data in [#8](https://github.com/KaiOppi/os-abuseipdb/issues/8) (waves of ~8-10 addresses).

### Schema
- New `aggregate` section (enabled, prefix_v6, prefix_v4, threshold, window_hours, permaban_after). New `prefix_aggregate` state table. Settings model bumped 0.1.9 → 0.1.10. Additive — existing installs are unaffected until the feature is explicitly enabled.

## [0.12.1] — 2026-08-04

### Fixed
- **Suricata category mapping: port scans were mislabelled as generic hacking (14 → 15).** The classtype→category matcher tested keywords in list order over the combined classtype + signature text, and the generic catch-all classtype buckets (*Misc Attack*, *bad-unknown*, *Potentially Bad Traffic* → all 15/Hacking) sat **before** the specific `scan` keyword. Many Emerging Threats `ET SCAN …` rules carry exactly such a generic classtype, so a real port scan was reported as category 15 instead of 14. The matcher now checks specific attack keywords first (weighting the signature over the classtype) and only falls back to the generic classtype buckets when nothing specific matched. Reported from real-world output on [#7](https://github.com/KaiOppi/os-abuseipdb/issues/7). Mapping logic only — no schema or config change.

## [0.12.0] — 2026-08-04

### Added
- **Suricata IDS/IPS alerts as a second reporting source ([#7](https://github.com/KaiOppi/os-abuseipdb/issues/7)).** A new **Suricata** tab lets the plugin report attacker IPs seen in Suricata's EVE JSON log to AbuseIPDB, in addition to the firewall-log reporter. Unlike reporting AbuseIPDB blacklist hits (which is intentionally *not* done — that would be circular), an IDS alert is your own first-hand detection of malicious behaviour against this host, which is exactly the evidence AbuseIPDB wants.
  - **Attacker heuristic:** only *inbound* attacks are reported — an alert's source IP must be public/external **and** its destination must be one of your own addresses (a directly-connected subnet, including the public WAN IP). Outbound traffic, LAN clients (v4 and IPv6 GUA), and both-endpoints-external transit are filtered out, reusing the reporter's existing WAN/local-source logic.
  - **Automatic category mapping:** Suricata classtypes are mapped to AbuseIPDB category IDs (network scan → 14, web-app attack → 21, SQL injection → 16, brute force → 18, trojan → 15+20, …), with a configurable fallback for unmapped classtypes.
  - **Severity floor:** choose the lowest alert priority to include (1 = high only, 2 = high+medium, default; 3 = everything).
  - **Shared safety machinery:** dry-run, pre-check, per-IP rate limit and the daily quota are shared with the firewall Reporter (one budget, one dedupe), and confirmed IPs feed the same self-defense / perma-block tables.
  - Runs on its own 5-minute cron when enabled. Requires Suricata EVE JSON logging (*Services: Intrusion Detection: Administration*).
- **Source column in the Log tab** — each report row is now tagged **Firewall** or **Suricata**, and the status banner shows a Suricata report count (today / total).

### Schema
- New `suricata` section (enabled, eve_log, min_hits, min_severity, default_categories, comment_template). Settings model bumped 0.1.8 → 0.1.9. Additive `source` column on the `reports` table (existing rows default to `firewall`). Existing installs are unaffected until the Suricata reporter is explicitly enabled.

## [0.11.2] — 2026-07-19

### Fixed
- **Plugin now registers as a managed plugin — no more "misconfigured" in the firmware GUI.** OPNsense marks a plugin as *configured* only when its name is listed in `config.xml → system/firmware/plugins`, and its `register.php` only ever registers a plugin that ships a `/usr/local/opnsense/version/<name>` metadata file. os-abuseipdb never shipped that file, so it could **never** be registered — the plugin list showed it as *misconfigured* regardless of how it was installed (even through the plugin manager). The package now ships `/usr/local/opnsense/version/abuseipdb` and self-registers in the post-install hook (`register.php install`), so a plain `pkg add`, a `pkg install`, and a plugin-manager install all leave it correctly registered. Upgrading an existing install fixes it automatically; to fix an older install without upgrading, run `configctl firmware resync`. **Packaging/metadata only — no functional code change vs 0.11.1.**

### Packaging
- **Available from the it-service-nf plugin repository (`pkg.itsnf.de`).** You can now add a signed pkg repository and install/update the plugin straight from the OPNsense plugin manager or `pkg upgrade`, instead of a manual `pkg add`. See the README → Installation for the one-time setup. The direct GitHub-release `pkg add` method still works unchanged.

## [0.11.1] — 2026-07-19

### Fixed
- **Architecture-agnostic package — installs cleanly on OPNsense 26.7 / FreeBSD 15.** The package was built as `FreeBSD:14:amd64`, so on OPNsense 26.7 (FreeBSD 15) `pkg add` rejected it with *"wrong architecture: FreeBSD:14:amd64 instead of FreeBSD:15:amd64"* (installable only with `-f`). Since the plugin ships only Python/PHP/XML/JS with no compiled binaries, the package is now built with a wildcard ABI/arch (`FreeBSD:*:*`), so a single package installs without `-f` on 26.1 (FreeBSD 14) and 26.7 (FreeBSD 15) alike. **Packaging metadata only — no code change vs 0.11.0.**

## [0.11.0] — 2026-07-08

### Added
- **AbuseIPDB account type selector (Free / Paid) on the Blacklist tab ([#6](https://github.com/KaiOppi/os-abuseipdb/issues/6)).** Free AbuseIPDB accounts can't set a confidence minimum and are capped at 10,000 blacklist rows — the API silently ignores `confidenceMinimum` and clamps the limit. Setting *Free* (the new default) now makes that explicit:
  - **UI:** the *Minimum confidence score* and *Maximum number of IPs* fields are locked (read-only, greyed) so nobody tunes knobs that have no effect. They stay populated, so switching to *Paid* restores your values.
  - **Backend:** the download no longer sends `confidenceMinimum` on a free account and clamps the limit to 10,000 server-side, matching what AbuseIPDB actually does.
  - *Paid* unlocks both fields (custom confidence, up to 500,000 IPs) for accounts that support it.

### Schema
- New `blacklist.account_tier` option field (`free` default / `paid`). Settings model bumped 0.1.7 → 0.1.8. Additive — existing installs default to *free*, which reproduces the previous 10k/default-confidence behaviour exactly.

## [0.10.0] — 2026-07-07

### Changed
- **Blacklist history window raised from 30 to 365 runs (Constantin's request, [#5](https://github.com/KaiOppi/os-abuseipdb/issues/5)).** In union / intersection mode the plugin keeps up to N past download snapshots and derives the active pf-alias from them. The old cap of 30 was only ~7.5 days at the common 6 h sync interval — too short to build a meaningful reputation window. `history_size` and the matching `history_threshold` now accept up to **365** (about 3 months at 6 h sync, or ~1 month at a 20-minute interval). Defaults are unchanged (N=7, M=4), so existing setups behave exactly as before.
- **GUI help note about DB size.** The *History size* field now spells out the storage impact (`N × max_ips × ~30 bytes`) with worked examples — 7 × 10k ≈ 6 MB, 120 × 10k ≈ 34 MB (~30 days), 365 × 10k ≈ 105 MB — so operators can pick a retention window with eyes open.

### Not changed / declined
- **Reporting IPs that were blocked by the AbuseIPDB blacklist rule itself** (also requested in [#5](https://github.com/KaiOppi/os-abuseipdb/issues/5)) is intentionally **not** implemented. It would violate the [AbuseIPDB reporting policy](https://www.abuseipdb.com/reporting-policy) (a block that only happened because of AbuseIPDB's own confidence score is circular reporting; pf drops the SYN before any TCP handshake completes, and UDP is not reportable at all). Hits on any non-`[os-abuseipdb]` rule — i.e. genuine independent evidence — are still reported as before, so no legitimate report is lost. See the issue thread for the full reasoning.
- No schema change: `history_size` / `history_threshold` are existing fields, only their upper validation bound moved. Settings model stays at 0.1.7.

## [0.9.0] — 2026-05-22

### Added
- **Operator whitelist (Constantin's request).** New top-level *Whitelist* tab with add / list / remove. Whitelisted IPs are treated as *never touch* across the entire plugin:
  - Reporter skips them before any `/report` or `/selfcare` action and logs the skip (`whitelist skip <ip> via <iface> (reporter)`).
  - Daily blacklist download filters them out of the pf alias regardless of mode (replace / persist-days / union / intersection); the dropped count is recorded per run.
  - `permaban_add` refuses to permaban a whitelisted IP with an explicit error.
  - `permaban_promote` (auto-promote scan) skips whitelisted candidates and surfaces the count in its JSON return.
  - A per-IP **skips/30d** counter in the Whitelist tab shows which entries are actually doing work (so dead entries can be pruned).
  - **Side-effect on add:** whitelisting an IP lifts it from any active self-defense entry *and* removes it from the perma-block list. Operator intent ("this IP is fine") applies retroactively.

- **Manual self-defense removal.** Each row of the *Self-Defense* tab now has three buttons: trash (drop just this entry, false-positive recovery), shield (move to whitelist), bolt (promote to permaban — pre-existing). A new red **Clear all** button at the top of the tab nukes every active self-defense entry in one shot (requires explicit confirm). Reporter will of course re-add a real attacker on the next run, so this is safe to use during recovery.

### Schema
- Two new SQLite tables (additive migration, no destructive change): `whitelist` (ip PK, added_ts, source, note) and `whitelist_skips` (rolling 30-day skip ledger, auto-pruned). Settings model bumped from 0.1.6 → 0.1.7.

### API
- Five new endpoints on `Api/ServiceController`:
  - `POST /api/abuseipdb/service/selfcare_remove`        (body: `ip`)
  - `POST /api/abuseipdb/service/selfcare_clear_all`     (body: `confirm=yes`)
  - `POST /api/abuseipdb/service/whitelist_add`          (body: `ip, source?, note?`)
  - `POST /api/abuseipdb/service/whitelist_remove`       (body: `ip`)
  - `GET  /api/abuseipdb/service/whitelist_list`         (query: `limit?`)
- Status panel + `stats.py` now expose a `whitelist_count` field.

### Notes
- No reporter-loop or blacklist-cron schedule change. Pure additive on top of v0.8.1.

## [0.8.1] — 2026-05-21

### Documentation
- **README install section: Suricata-warning added.** On a busy production OPNsense with active Suricata IDS we hit a reproducible install-time outage: the `+POST_INSTALL` hook does `service configd restart` (standard practice for OPNsense plugins so configd reloads `actions.d`), and during that stop+start window os-suricata fired an `ids list rulemetadata` request that crashed configd on startup — taking the whole web UI with it. The fix on the affected box was to stop Suricata, restart configd cleanly, then continue. The README now tells Suricata users to `service suricata stop` before installing the plugin and to start it back afterwards. Boxes without Suricata are unaffected and don't need any extra steps.

### Notes
- No code, model, or behavioural changes — pure documentation update. Safe to upgrade from 0.8.0; the package contents are identical aside from build metadata.
- A SIGHUP-based graceful reload was attempted as an in-hook fix but Python's default SIGHUP handler is `terminate`, which made the outage *worse* (configd died immediately on SIGHUP, then there was no daemon to restart). We have left `service configd restart` in place as it has worked on all other production boxes (home, bergstrasse, MKG, multiple Reddit-reported installs). The root cause sits in os-suricata's `ids list rulemetadata` action, not in our hook.

## [0.8.0] — 2026-05-18

### Added
- **API-quota tracking per endpoint.** Until now the *AbuseIPDB Status* panel only showed `X-RateLimit-Remaining` from the most recent `/blacklist` call — refreshed at most once a day by the 03:13 download cron. v0.8 captures the header on **every** API call (`/check`, `/report`, `/blacklist`) and persists it in a new SQLite table `api_quota_log`. The status panel now renders three independent rows, each with its current remaining count, daily limit, when the header was last seen, and how long until reset. Useful when one account is shared across multiple OPNsense boxes: each box's UI now shows what its own traffic has cost in real time.

- **Blacklist snapshot rotation (union / intersection mode).** Two new modes for the daily download, controlled by three new settings on the *Blacklist* tab:
  - `history_mode = off` (default, replaces the table each day — original behaviour)
  - `history_mode = union, history_size = N` — keep every IP we've seen across the last N runs, regenerate the alias as `SELECT DISTINCT ip`. Sliding-window variant of the v0.7 `persist_days` mode.
  - `history_mode = intersection, history_size = N, history_threshold = M` — only keep IPs that appear in at least M of the last N runs. Filters out drive-by hits, leaves the constant repeat-offenders. Typical setup `N=7, M=4` yields ~3-5k IPs from a 10k daily download.

  Storage: two new tables `blacklist_snapshots` and `blacklist_snapshot_meta`. DB cost is bounded by `N × max_ips`; e.g. `N=7 × 10k = 70k` rows ≈ 6 MB with index. Pf table is regenerated from a `GROUP BY ip HAVING COUNT(*) >= M` query — sub-100ms even at 30 snapshots.

- **Snapshot history view.** New foldable section at the bottom of the *AbuseIPDB Status* panel, automatically shown when at least one snapshot exists. Lists snapshot ID, fetched-at timestamp, IP count, and the quota header that came back with that fetch — last 30 snapshots, newest first.

- **Stacked v4 / v6 bars in the Statistics tab.** Per-interface and 14-day charts now render a second purple segment showing the IPv6 share alongside the blue (or green for the daily series) IPv4 portion. Tooltips on each segment give the exact count. Backed by a new `by_iface_v6` map and `count_v6` per daily entry in the stats payload.

- **Configurable row limit on the Self-Defense list.** Dropdown (50 / 100 / 200 / 300 / 500) on the *Self-Defense* tab, default 300. Picks how many entries the GUI requests from the `selfcare_list` endpoint and renders. The header now shows *Shown X of Total* so it's obvious when the active set exceeds the limit. Up until 0.7.3 the GUI was hard-wired to 200 — meaning installations with more than 200 active entries (which v6 made considerably more common) had older rows silently hidden.

### Fixed
- **SQLite-Lock-Race in record_quota.** The new `record_quota()` helper opened its own short-lived writer connection per API call. While the reporter loop had its own long-lived connection open, the second writer hit `database is locked` and the surrounding pre-check failed with `SKIP: precheck failed (check failed: database is locked)`. Three layers of fix:
  - `get_db()` now sets `PRAGMA journal_mode=WAL` + `PRAGMA busy_timeout=5000` — readers and writers no longer block each other.
  - `record_quota()` is wrapped in defensive try/except so a transient DB error never kills the surrounding `/report` or `/check` flow.
  - `check_abuseipdb(...)` and `submit_report(...)` accept the caller's open DB connection as `db=...` kwarg and pass it through to `record_quota`, so the reporter's hot path no longer opens a second connection at all.

### Notes
- Schema bump `Abuseipdb.xml`: `0.1.5 → 0.1.6`. Three new fields under `<blacklist>` (`history_mode`, `history_size`, `history_threshold`). No data migration needed.
- The new SQLite tables (`api_quota_log`, `blacklist_snapshots`, `blacklist_snapshot_meta`) are created lazily on first `get_db()` call; existing installs pick them up on the next reporter or download cron without any operator action.
- Live-tested for ~24 hours on a production OPNsense (Home) before release. Reporter logged ~100 reports/day, quota rows arrived as expected, no further lock errors after the WAL fix, no configd or webgui regression.

## [0.7.3] — 2026-05-16

### Changed
- **Perma-Block notes are now human-readable.** The auto-promote path wrote things like `3 selfcare hits, first=1778183106 last=1778898603` into the perma-block ledger — nobody reads epoch timestamps. The reporter's `maybe_promote()` and the manual `permaban_promote.py` action now format timestamps with `time.strftime("%Y-%m-%d %H:%M", localtime)`, producing notes like `3 selfcare hits between 2026-05-07 14:23 and 2026-05-15 18:30` and `3 selfcare hits within 14d, last 2026-05-15 18:30`. Future rows are clean; existing rows in the DB stay as-is (no in-place migration runs).

## [0.7.2] — 2026-05-16

### Fixed
- **`&lt;` shown literally in the Reports tab.** One reporter SKIP-message contained a raw `<` character (`"SKIP: precheck confidence 0<25 ..."`), which OPNsense's Phalcon JSON layer HTML-encodes on the way to the browser as an XSS defence. The frontend then renders `&lt;` literally, since `jQuery.text()` treats the entity as text. Replaced the operator with the word *below* so the entire reporter pipeline stays HTML-safe without depending on the framework to round-trip entities cleanly.

  Net effect for operators: new SKIP rows read `"SKIP: precheck confidence 0 below 25 (...)"` instead of the half-encoded version. Old rows in the local DB are untouched — if they bother you, run `sqlite3 /var/db/abuseipdb/state.sqlite "UPDATE reports SET message = REPLACE(message, '<', ' below ') WHERE message LIKE 'SKIP: precheck confidence%<%'"` once.

## [0.7.1] — 2026-05-16

### Changed
- **Default report comment now identifies the plugin by name.** Changed from `Blocked by OPNsense firewall; …` to `Blocked by os-abuseipdb; …`. Affects the model default (so fresh installs and saved-without-customisation operators get the new wording) and the in-code fallback used when the configured template has a placeholder typo. Operators who already customised the *Comment template* field on the Reporter tab keep their own text untouched.

## [0.7.0] — 2026-05-16

### Added
- **Persistent blacklist mode (sleeper protection).** The downloader has been a *replace* operation since v0.1: every run swapped the pf table for today's AbuseIPDB top-N (default 10k). An IP that drops out of the hot list — but reactivates a week later — was no longer in our table when it came back. New optional persistent mode keeps every IP we've ever seen for a configurable number of days, refreshing the `last_seen` timestamp every time it reappears in the daily pull. Sleepers stay covered until their first-seen age crosses the TTL.

  New setting on the Blacklist tab: **Persist days** (default `0` = original replace behaviour for back-compat; set to e.g. `30` to enable). New SQLite table `blacklist_persistent(ip, first_seen_ts, last_seen_ts)`. The pf table is regenerated from the merged set on every download. Cleanup is integrated into the download path itself — `DELETE FROM blacklist_persistent WHERE first_seen_ts < (now - persist_days*86400)`.

  Wishlist item from community user *Constantin* (CKbeats), motivated by the observation that AbuseIPDB's `/blacklist` endpoint always returns the currently-hottest IPs and his attack logs showed re-activation cycles longer than the daily snapshot window.

- **Configurable report comment template.** The `comment` field submitted to `POST /api/v2/report` was a hardcoded string `Blocked by OPNsense firewall; N hits, proto=…, ports=…`. New setting **Comment template** on the Reporter tab lets the operator change it. Supported placeholders: `{count}`, `{protos}`, `{ports}`, `{iface}`, `{src_ip}`. Default keeps the historical text. Bad templates (typo / unknown placeholder) fall back to the built-in form so a config mistake never blocks a reporter run. Output is capped at 1000 characters before submit (AbuseIPDB API limit is 1024).

  Also from Constantin's wishlist (marked "nice to have, no must").

### Notes
- Schema bump `Abuseipdb.xml`: `0.1.4 → 0.1.5`. Two new fields: `blacklist.persist_days` (IntegerField, default 0) and `reporter.comment_template` (TextField, default = historical hardcoded string). No data migration needed.
- The persistent blacklist table is created on first `get_db()` call, so existing installs see no migration step. Memory growth is bounded by `persist_days` × daily new-IP rate; at 30 days expect roughly 30-100 k entries depending on overlap.
- Constantin's third request — mirroring the AbuseIPDB blacklist into the Self-Defense table — was intentionally not implemented. With persistent blacklist mode the same protection is delivered by the blacklist table itself, without the conceptual confusion of treating an external snapshot as a local hit (which would otherwise feed the Perma-Block auto-promote threshold).

## [0.6.2] — 2026-05-16

### Fixed
- **Reporter no longer treats LAN block events as attacker traffic.** A consequence of opening up IPv6 in v0.6.0: until now the reporter accepted every `block`-event from the filter log, regardless of which interface it came from. For IPv4 that was harmless because LAN-side blocks always have RFC1918 source addresses and `is_private()` filtered them out. For IPv6 the LAN clients carry **globally routable GUA** addresses out of the WAN-delegated prefix (or a previously-cached prefix while the ISP rotates), so the global-vs-private split no longer maps to local-vs-remote — a `block,in` event on the LAN interface produced by an iPhone with a stale Privacy-Extension address was getting `/check`-ed against AbuseIPDB every reporter cycle. No successful `/report` ever went out (the pre-check kept them under the confidence threshold), but the lookup traffic alone is leakage we don't want.

  Two new defensive layers in `reporter.py`:
  - **WAN-interface filter.** `parse_line()` now keeps a parsed record only if (a) the event direction is `in` (outbound drops are local-egress events whose "source" is one of our own clients) and (b) the physical interface name appears in the set returned by the new `get_wan_iface_phys_names()` helper in `_common.py`. That helper reads `/conf/config.xml` and flags any interface configured with a static gateway, gateway6, or a dynamic family like `pppoe`, `dhcp`, `slaac`, `track6`, etc.
  - **Connected-network filter.** Sources whose address falls inside any directly-connected subnet on this box are skipped via the new `is_local_source()` check, fed by `get_local_networks()` (parses `ifconfig` for v4 + v6 networks). Catches LAN clients with current-prefix GUAs.

  Belt-and-braces: a stale-prefix GUA from a prior PD rotation is caught by the WAN-interface filter even though the connected-network filter doesn't know about the previous prefix.

  Verified on the home OPNsense: WAN set resolves to `{'pppoe0','vlan03'}`, local-networks list picks up all VLAN subnets plus the `2a11:fb80:296:400::/60` PD plus the WireGuard tunnels. A `vlan01` LAN-side `block,in` line with source `2a11:fb80:2e1:3700::1a8c` (stale prefix) now drops out of the reporter pipeline.

### Notes
- No schema change, no migration. The new helpers are read-only against `ifconfig` and `/conf/config.xml`.
- Single-WAN, dual-WAN, and PPPoE setups all worked in testing. If `get_wan_iface_phys_names()` returns an empty set (config read failure), the WAN-interface filter is treated as inactive so an unexpected parser breakage doesn't silently drop every event — the per-IP defences (`is_private`, `is_local_source`, own-rule marker) still run.

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
