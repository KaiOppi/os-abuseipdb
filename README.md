# os-abuseipdb — OPNsense AbuseIPDB Integration

OPNsense plugin for bidirectional [AbuseIPDB](https://www.abuseipdb.com) integration:

- **Blacklist** — downloads the AbuseIPDB blocklist into a pf table and auto-creates a firewall alias + block rule.
- **Reporter** — parses the OPNsense firewall log and submits attacker IPs back to AbuseIPDB (bidirectional participation in the threat-intelligence network).
- **Suricata reporter** — optional second source that submits attacker IPs from Suricata IDS/IPS alerts (EVE JSON log). Only inbound attacks against this host are reported; Suricata classtypes map automatically to AbuseIPDB categories. Shares the reporter's safety settings and daily quota.
- **Self-Defense** — TTL-based local blocklist populated from reporter submits; closes the gap while AbuseIPDB's community catches up.
- **Perma-Block** — repeat offenders that come back after their Self-Defense TTL expired get auto-promoted to a permanent block list, with a per-IP hit counter (cumulative across reboots) so you see exactly how often each entry actually triggered.
- **Whitelist** — operator-managed *never touch* list: whitelisted IPs are excluded from reports, self-defense, perma-block, and the downloaded blacklist. Designed for known-good sources (remote support tools, monitoring, partner networks) that occasionally trip the reporter. Adding an IP automatically lifts any active self-defense or perma-block entry for it.
- **Configurable rule style** — choose where the plugin places its block rules: classic `Firewall: Rules: WAN` (legacy), the modern `Firewall: Automation: Filter` tab, or *None* if you'd rather craft rules yourself against the maintained aliases. Style switches auto-clean up rules in the previously-used location.
- **Per-interface tracking** — every report, self-defense entry and perma-block hit knows which uplink it came in over; useful for multi-WAN setups (failover or load-balance) to see *where* the attack pressure lands.
- **Statistics tab** — per-interface counters and a 14-day trend for reports and self-defense additions; helps spot which uplink is the noisier target and how the load develops over time.
- **Dashboard widget** — live stats (blocklist size, last download, quota, reports, self-defense active/total, perma-block size, whitelist size).
- **Fire & forget** — cron jobs are created automatically when you enable the feature (daily download, 5-minute reporter cycles, hourly self-defense cleanup, daily perma-block sweep, 5-minute hit-counter sampler).

> **Status:** public beta (v0.12.0). Running in production on several OPNsense boxes (26.1 / FreeBSD 14 and 26.7 / FreeBSD 15). Looking for community testers — please open an issue or a r/opnsense reply with feedback.

## Screenshots

| Settings | Self-Defense live view |
|---|---|
| ![General tab](docs/screenshots/01-general.png) | ![Self-Defense tab with Currently blocked table](docs/screenshots/02-selfcare.png) |

| Report log | Dashboard widget |
|---|---|
| ![Log tab](docs/screenshots/03-log.png) | ![Dashboard widget](docs/screenshots/04-widget.png) |

## Installation

> ⚠️ **Heads up if you run Suricata (Intrusion Detection)**
> On busy boxes with `os-suricata` enabled we have seen the configd daemon
> crash during the post-install hook because configd received an
> `ids list rulemetadata` request from the IDS while it was reloading.
> If you run Suricata, **stop it first**, then install, then start it back:
>
> ```sh
> service suricata stop
> # ... install commands below ...
> service suricata onestart
> ```
>
> Boxes without Suricata are unaffected.

In the OPNsense shell (Console → option 8), first install the Python dependency
(needed by **both** methods below):

```sh
# The package name depends on the Python version on your OPNsense:
# 26.1 LTS uses py311, newer builds py313.
# Check with: python3 -c 'import sys;print(f"py{sys.version_info[0]}{sys.version_info[1]}-requests")'
pkg install -y py313-requests   # for Python 3.13 (OPNsense 26.1.5+)
# pkg install -y py311-requests # for older 26.1.x
```

### Method A — it-service-nf plugin repository *(recommended)*

Add the signed repository once; after that you install and update os-abuseipdb
straight from the OPNsense plugin manager (**System → Firmware → Plugins**) or
`pkg upgrade`, and it shows up as a properly managed plugin.

```sh
# One-time: add the repository (installs the public key + repo config, runs pkg update)
fetch -o - https://pkg.itsnf.de/bootstrap.sh | sh

# Install (or do it from System → Firmware → Plugins in the GUI)
pkg install -y os-abuseipdb
```

<details><summary>What the bootstrap does (manual equivalent)</summary>

```sh
fetch -o /usr/local/etc/pkg/itsnf.pub https://pkg.itsnf.de/latest/itsnf.pub
cat > /usr/local/etc/pkg/repos/itsnf.conf <<'EOF'
itsnf: {
  url: "https://pkg.itsnf.de/latest",
  signature_type: "pubkey",
  pubkey: "/usr/local/etc/pkg/itsnf.pub",
  priority: 5,
  enabled: yes
}
EOF
pkg update
```

The repository catalogue is RSA-signed; pkg verifies it against the public key
you just installed. The repository currently serves this plugin (and other
it-service-nf OPNsense plugins).
</details>

### Method B — direct package *(no external repository)*

```sh
pkg add https://github.com/KaiOppi/os-abuseipdb/releases/download/v0.12.0/os-abuseipdb-0.12.0.pkg
```

Since v0.11.2 the plugin self-registers on install, so this method also lands as
a properly registered plugin in the GUI (no *misconfigured* flag).

---

Then go to **Firewall → AbuseIPDB**. The post-install hook flushes the
WebGUI menu/ACL caches automatically — no logout+login required.

## Upgrading

If you installed via the **repository (Method A)**, just upgrade normally —
`pkg upgrade os-abuseipdb`, or **System → Firmware** in the GUI, which offers the
new version automatically.

If you installed via the **direct package (Method B)**, install the new package
over the old one with `-f` (force). Your settings, cron jobs and firewall aliases
live in `config.xml`, so they are preserved — you do **not** need to uninstall
first:

```sh
# Replace the version with the latest from the releases page
pkg add -f https://github.com/KaiOppi/os-abuseipdb/releases/download/v0.12.0/os-abuseipdb-0.12.0.pkg
```

Notes:
- Check the version you currently have with `pkg query %v os-abuseipdb`, and the
  newest one on the [releases page](https://github.com/KaiOppi/os-abuseipdb/releases).
- The Python dependency (`py311-requests` / `py313-requests`) is a one-time
  install — it stays across upgrades, so you don't need to reinstall it.
- Same Suricata caveat as above: if you run `os-suricata`, `service suricata stop`
  before the `pkg add -f`, then `service suricata onestart` afterwards.
- If the GUI still looks like the old version after upgrading, hard-refresh the
  page (Ctrl-F5 / Cmd-Shift-R) to clear the browser cache.

## Configuration

### General

1. Tab **General**
   - Tick `Plugin enabled`
   - Paste your `API Key` (80-char hex, free tier at [abuseipdb.com](https://www.abuseipdb.com/account/api))
2. **Save** — the **Test connection** button verifies the key immediately.

The same tab carries a **Block rules** section that controls where and whether the plugin manages its three block rules (Blacklist, Self-Defense, Perma-Block). See [Block rules](#block-rules) below.

### Block rules

The plugin maintains three pf-table aliases — `abuseipdb_blacklist`, `abuseipdb_selfcare`, `abuseipdb_permaban` — and (optionally) one block rule per alias. *Where* and *whether* those block rules live is up to you:

- **Rule style** (dropdown):
  - **Classic** *(default)* — rules go into the legacy `<filter><rule>` list, visible under `Firewall: Rules: WAN`. Existing installs upgrade transparently.
  - **Automation** — rules go into the modern `OPNsense\Firewall\Filter` model, visible under `Firewall: Automation: Filter` (the new "Rules" tab). Sequence is set to `1` so plugin rules fire ahead of hand-curated ones.
  - **None** — plugin keeps the aliases up to date but does not create any rules. Useful when you want full manual control over rule order in the new Rules tab.
- **Manage block rules on save** (checkbox) — when off, the plugin removes any previously-placed rules and never touches firewall rules again. Aliases are still maintained.

Switching styles is safe: the plugin remembers the previously-applied style and removes its rules from the old location before creating fresh ones in the new location. No orphans, no duplicates.

### Blacklist

Tab **Blacklist** → enable.

On save the following is created automatically:
- Firewall alias `abuseipdb_blacklist` (type *External*)
- WAN block rule with source = the alias, logging enabled
- Cron job: daily download at 03:13

Default values (configurable):
- `AbuseIPDB account type` — **Free** (default) or **Paid**. On a free account the blacklist endpoint ignores the confidence minimum and caps the list at 10,000 IPs, so the two fields below are locked (read-only) to avoid confusion; the download also skips sending `confidenceMinimum` and clamps the limit to 10k server-side. Switch to **Paid** only if your account supports custom confidence and larger lists.
- `Minimum confidence score` — 90 (only high-quality hits). *Paid accounts only.*
- `Maximum number of IPs` — 10000 (free-tier per-call limit; up to 500,000 on paid)
- `Include IPv6 entries` — off by default. The AbuseIPDB blacklist endpoint returns IPv4 only; enable this to make a second explicit IPv6 call and merge both families into the pf table. Costs one extra blacklist quota slot per run.
- `Persist days` — 0 (off). Legacy v0.7 retention: keep every IP for N days from first sight, even after it drops out of the daily top-N. Superseded by History mode below — leave at 0 unless an existing setup relies on it.
- `History mode` — **Off** (default), **Union**, or **Intersection**. *Off*: each download replaces the alias with today's list. *Union*: keep every IP seen across the last N downloads (sliding window, same effect as Persist days but bounded). *Intersection*: only include IPs that appear in at least M of the last N downloads — reputation-filtered, smallest alias, lowest false-positive rate.
- `History size (N)` — number of past download snapshots kept in union/intersection mode. Default 7, up to **365** (~3 months at a 6 h sync). Peak DB cost ≈ N × max_ips × 30 bytes.
- `History threshold (M of N)` — intersection mode only: minimum number of snapshots an IP must appear in before it enters the alias. Default 4; set close to N for the strictest filter.
- `Block on interface(s)` — WAN. Accepts either the internal identifier (`wan`, `opt1`, ...) or the friendly name from Interfaces → Assignments (`WAN`, `DSL`, ...). Multiple comma-separated entries turn the rule into a floating rule on the listed interfaces (multi-WAN / failover).

### Reporter

Tab **Reporter** → enable.

On save the following is created automatically:
- Cron job: reporter run every 5 minutes (parses `/var/log/filter/latest.log`)

Default values:
- `Dry-run` — **on**. Candidates are logged as "would report" but not actually submitted. Keep this on for 24h after enabling the reporter so you can verify the selected hits are real attack traffic.
- `Pre-check IP against AbuseIPDB` — **on**. Before reporting, the candidate IP is looked up via `/api/v2/check` and skipped if nobody else has flagged it (`confidence < precheck_min_confidence`). Costs one API call per candidate, dramatically reduces false positives.
- `Minimum hits before report` — 3 (dedupe against noise)
- `Rate limit per IP (min)` — 15 (max one report per IP per window)
- `Daily report quota` — 900 (below the free-tier 1000-per-day limit)
- `Default categories` — `14,15` (PortScan + Hacking)
- `Report comment template` — text sent with each report, with placeholders `{count}` `{protos}` `{ports}` `{iface}` `{src_ip}`. Defaults to `Blocked by os-abuseipdb; {count} hits, proto={protos}, ports={ports}` (trimmed to 1000 chars; falls back to the default on a bad template).

> **Note:** IPs blocked by the plugin's own blacklist rule are **not** reported back (that would be circular reporting).

### Suricata reporter

Tab **Suricata** → enable. A second reporting source next to the firewall-log
reporter: it reads Suricata's EVE JSON log and reports the attacker IPs behind
IDS/IPS alerts. This is legitimate first-hand evidence (a real detection against
your host), unlike blacklist hits — so it is fully in scope for AbuseIPDB.

Prerequisite: enable Suricata's EVE JSON output under
**Services: Intrusion Detection: Administration** (the `eve.json` log).

On save a cron job runs the Suricata reporter every 5 minutes (parses the
configured EVE log). What gets reported:

- Only **inbound attacks against this box** — an alert's source IP must be
  public/external *and* its destination must be one of your own addresses
  (a directly-connected subnet, including the public WAN IP). Outbound traffic,
  LAN clients (IPv4 and IPv6 GUA) and both-endpoints-external transit are dropped.
- Suricata classtypes are mapped to AbuseIPDB categories automatically
  (network scan → 14, web-app attack → 21, SQL injection → 16, brute force → 18,
  trojan → 15+20, …); unmapped classtypes use the configurable fallback.

Settings:
- `Minimum alert priority` — 1 = high only, 2 = high+medium (default), 3 = all
  (also low-severity/policy rules — noisy).
- `Minimum alerts before report` — 1 (report on the first alert; raise to suppress isolated hits).
- `Fallback categories` — used only when a classtype can't be mapped (default `15` = Hacking).
- `Comment template` — placeholders `{count}` `{signatures}` `{categories}` `{ports}` `{protos}` `{iface}` `{src_ip}`.

> The submit-safety settings — **dry-run, pre-check, per-IP rate limit and the
> daily quota — are shared with the Reporter tab.** Both sources draw from one
> daily budget and one per-IP dedupe window, and confirmed IPs feed the same
> Self-Defense / Perma-Block tables. Keep dry-run on for the first 24 h here too.

### Self-Defense

Tab **Self-Defense** → enable.

Every IP the reporter successfully submits to AbuseIPDB is also dropped into a **local** pf table `abuseipdb_selfcare` with a TTL (default 72 h). A second block rule — same interfaces as the blacklist rule — drops traffic from that table. An hourly cleanup cron expires entries whose TTL has passed.

This closes the window between "we saw the attack" and "AbuseIPDB's community-wide blacklist catches up with this IP". Attackers hitting you get blocked locally immediately.

Default values:
- `Block duration (hours)` — 72 (3 days; range 1 … 8760)

Trigger conditions for adding an IP to the self-defense table:

- **With pre-check on** (default): IP is added as soon as `/api/v2/check` confirms `confidence >= precheck_min_confidence` — independent of whether the report itself goes through. This means self-defense keeps filling even when the daily report quota is exhausted, the reporter is in dry-run, or AbuseIPDB temporarily rejects the submit. Pre-check uses its own AbuseIPDB endpoint quota (1000 `/check`/day on the free tier, separate from `/report`).
- **With pre-check off**: IP is added only after a successful real report, since there's no confidence signal otherwise (we won't blindly local-block on raw log hits).

The current self-defense list is visible directly in the **Self-Defense** tab under the settings ("Currently blocked"). Each entry shows the interface it came in over (e.g. `WAN`, `DSL`, `LWL`).

### Perma-Block

Tab **Perma-Block** → enable.

Repeat offenders — IPs that come *back* into the Self-Defense list after their TTL expired — get auto-promoted to a permanent block list (pf table `abuseipdb_permaban`). They stay blocked until you manually remove them, regardless of TTL. No AbuseIPDB report is submitted on promotion: the decision to publicly flag an IP stays with you.

Default values:
- `Promote after N occurrences` — 3 (must reappear three times within the window)
- `Window (days)` — 14 (the threshold is counted across the last 14 days)

Promotion happens at two points:
- **Inline:** the reporter sees an IP it already knows from `selfcare_history` and promotes immediately.
- **Sweep:** a daily cron (`abuseipdb permaban_scan`, 03:23) catches anything missed (manual edits, reporter downtime, config changes).

The Perma-Block tab shows the live list with two telemetry columns:
- **Hits** — cumulative pf-counter total per IP, persistent across reboots. A 5-minute cron (`abuseipdb permaban_count`) reads the in-kernel counter (`pfctl -t abuseipdb_permaban -T show -vv`), folds the delta into the persisted total, and survives reboots / `pfctl -T zero` by detecting counter resets.
- **Last hit** — timestamp of the last counter advance.

You can also add IPs manually (e.g. for a problem source you've identified outside the reporter path) — the **Add to Perma-Block** form takes an IP plus an optional note.

### Whitelist

Tab **Whitelist**.

An operator-managed *never touch* list for known-good sources that keep tripping the reporter — remote-support tools (PCVisit, AnyDesk, TeamViewer relay IPs), monitoring probes, partner networks, your own VPS jumphost, etc. Whitelisted IPs are honoured across the whole plugin:

- **Reporter** skips them before any `/report` or self-defense action and records the skip.
- **Daily blacklist download** filters them out of the `abuseipdb_blacklist` pf alias regardless of mode (replace / persist-days / union / intersection).
- **`permaban_add`** refuses with an explicit error if the IP is whitelisted.
- **Auto-promote scan** skips whitelisted candidates.

Unlike the three other lists, the whitelist does **not** create its own pf table or block rule — it's a software gate in front of the existing actions. It only prevents *this plugin* from acting on the IP; other firewall rules, IDS/IPS plugins, etc. are untouched.

**Side-effect on add:** if the IP is currently in self-defense or perma-block, those entries are lifted automatically (DB + pf table). So in the typical "I see PCVisit's IP got self-defended, that's a false positive" case, one click on the 🛡️ shield button in the Self-Defense tab — or one manual whitelist add — both whitelists the IP *and* clears the existing block in a single operation.

Each row in the whitelist table shows a **skips/30d** counter (rolling 30-day window) so you can see which entries are doing actual work and prune the dead ones later.

#### Manual self-defense controls

The Self-Defense tab also has three per-row buttons for ad-hoc operator action:

- 🗑️ **Trash** — drop just this self-defense entry without permabanning it (false-positive recovery).
- 🛡️ **Shield** — move the IP to the whitelist (also lifts the self-defense + any existing perma-block entry).
- ⚡ **Bolt** — promote to Perma-Block (existing).

A red **Clear all** button at the top of the Self-Defense tab wipes every active entry in one shot (confirm required). Use this when several false positives slipped through at once. Real attackers will be re-added on the next reporter run, so this is safe during recovery.

### Statistics

Tab **Statistics** — aggregated views over the data that the reporter and self-defense path collect:

- **Per-interface counters**
  - Self-defense: currently active and total ever added, broken down by interface
  - Reports: today and total, broken down by interface

  In multi-WAN setups (failover or load-balance) this answers *which uplink is the noisier target* — e.g. `WAN: 142, DSL: 31, LWL: 8`.

- **14-day trend (daily buckets)**
  - Reports submitted per day
  - Self-defense IPs added per day

  Helps see whether the attack pressure is steady, ramping up, or whether yesterday's spike was an outlier.

The reporter writes the OPNsense interface **identifier** (`wan`, `opt1`, `opt2`, ...) — stable across renames. The friendly name (`WAN`, `DSL`, `LWL`) you assigned in *Interfaces → Assignments* is resolved to display only, so renaming an interface later does not invalidate historic data.

## Dashboard widget

**Lobby → Dashboard → Add widget → "AbuseIPDB"** — shows blocklist size, last download time, API quota, reports today/total, and self-defense entries (active / total).

## Verification

```sh
# Blocklist in pf table
pfctl -t abuseipdb_blacklist -T show | wc -l

# Stats as JSON
configctl abuseipdb stats

# Manual download (costs one API call)
configctl abuseipdb download

# Trigger reporter manually
configctl abuseipdb report

# Self-defense list in pf table
pfctl -t abuseipdb_selfcare -T show | wc -l

# Show active self-defense entries (with expiry timestamps)
configctl abuseipdb selfcare_list 100

# Run expiry cleanup manually
configctl abuseipdb selfcare_cleanup

# Perma-Block list in pf table
pfctl -t abuseipdb_permaban -T show | wc -l

# Perma-Block entries with hit counters
configctl abuseipdb permaban_list 500

# Trigger a Perma-Block auto-promote scan manually
configctl abuseipdb permaban_scan

# Run the hit-counter sampler once (normally every 5 min via cron)
configctl abuseipdb permaban_count
```

## Uninstall

```sh
pkg remove os-abuseipdb
```

- The firewall alias and block rule **stay in place** (remove them manually if you want to).
- The state directory `/var/db/abuseipdb/` stays (holds report history in SQLite).

## Requirements

- OPNsense 26.1 or newer
- `py311-requests` or `py313-requests` (must be installed before `pkg add` — see [Installation](#installation))
- AbuseIPDB API key (free tier is enough for a single system)

## Roadmap

**Done:**
- [x] Plugin scaffolding + GUI
- [x] Blacklist downloader
- [x] Auto-setup of alias + block rule (multi-interface, floating)
- [x] Reporter (firewall log → AbuseIPDB) with dry-run, pre-check, noise filter
- [x] Cron integration (download + reporter + cleanups)
- [x] Dashboard widget
- [x] Report log viewer in the plugin + refresh button
- [x] Quick-jump navigation to alias / rule / cron / log
- [x] FreeBSD pkg + GitHub release
- [x] Self-Defense local blocklist (TTL-based, auto-populated from reporter submits)
- [x] Per-interface tracking + Statistics tab (per-interface counters, 14-day trend)
- [x] Perma-Block — auto-promote repeat offenders that come back after their Self-Defense TTL
- [x] Per-IP hit counter on the Perma-Block list, reboot-safe (cumulative pf-counter total + last-hit timestamp)
- [x] Configurable rule style — classic `<filter><rule>` / Automation Filter model / none, with auto-cleanup on style switch and a "manage block rules on save" toggle for full manual control
- [x] IPv6 support across reporter, blacklist and perma-block (v0.6.0)
- [x] Persistent blacklist with TTL + configurable report comment template (v0.7.0)
- [x] Blacklist snapshot rotation (union / intersection reputation filter), per-endpoint API quota tracking, IPv4/IPv6 stacked stats (v0.8.0)
- [x] Operator whitelist + manual self-defense removal (v0.9.0)
- [x] Blacklist history window up to 365 snapshots (v0.10.0)
- [x] Free / Paid AbuseIPDB account selector (v0.11.0)
- [x] Architecture-agnostic package — one build for FreeBSD 14 (26.1) and FreeBSD 15 (26.7) (v0.11.1)
- [x] Registers as a managed OPNsense plugin + signed pkg repository (`pkg.itsnf.de`) for GUI install/updates (v0.11.2)
- [x] Suricata IDS/IPS alerts as a reporting source, with automatic classtype→category mapping (v0.12.0, [#7](https://github.com/KaiOppi/os-abuseipdb/issues/7))

**Open:**
- [ ] Rule-to-category mapping UI (currently default categories only)
- [ ] German translation (deferred to the Community Crowdin workflow)

**Later / post-1.0:**
- [ ] **Service-log integration** — catch attacks against local services (Postfix, sshd, WebGUI brute-force, FTP) by parsing their logs, not just firewall blocks. Optional auto-ban into the pf table so attackers are blocked and reported in one step.
- [ ] Zenarmor alert events as an additional reporting source
- [ ] GeoIP enrichment in the log viewer (ASN/country per IP)

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full per-version history.

## Feedback / bug reports

- GitHub issues: <https://github.com/KaiOppi/os-abuseipdb/issues>
- Constructive feedback, feature ideas and bug reports are very welcome while the plugin is in beta.

## Acknowledgements

Developed with [Claude Code](https://claude.com/claude-code) as a pair-programming assistant. Architecture decisions, production testing, and every deployment to a live OPNsense were driven by the maintainer; Claude Code sped up the grind of boilerplate, scaffolding, and hunting down OPNsense-specific gotchas.

## License

BSD 2-Clause — see [LICENSE](LICENSE).

## Maintainer

Kai Schlestein · bartsi@gmail.com
