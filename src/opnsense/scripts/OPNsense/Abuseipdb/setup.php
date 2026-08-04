<?php
/*
 * Ensure firewall aliases + (optional) block rules for os-abuseipdb exist.
 *
 * Aliases live in the modern OPNsense\Firewall\Alias model (always managed,
 * regardless of rule-style settings).
 *
 * Block rules can be placed in three styles, controlled by rules.style:
 *   - classic    → legacy <filter><rule> in config.xml
 *                  ("Firewall → Rules → WAN" tab)
 *   - automation → modern OPNsense\Firewall\Filter model
 *                  ("Firewall → Automation → Filter" tab)
 *   - none       → no plugin-managed rule; user crafts rule(s) themselves
 *                  against the maintained aliases.
 *
 * On every save the plugin compares the previously-applied style against
 * the currently-requested one. If they differ, the rules placed in the
 * old style are removed before fresh ones are created in the new style.
 * The same cleanup runs when rules.manage is turned off.
 *
 * Idempotency: rules are matched by description marker, so a save that
 * doesn't change anything material results in zero writes.
 *
 * Copyright (c) 2026 Kai Schlestein
 * BSD 2-Clause.
 */

require_once("config.inc");
require_once("util.inc");

use OPNsense\Core\ACL;
use OPNsense\Core\Config;
use OPNsense\Firewall\Alias;
use OPNsense\Firewall\Filter as FwFilter;
use OPNsense\Cron\Cron;
use OPNsense\Abuseipdb\Abuseipdb;

// Make sure the ACL cache picks up our page-firewall-abuseipdb privilege.
try {
    $acl = new ACL();
    $acl->invalidateCache();
    $acl->persist(false);
} catch (\Throwable $e) {
    // non-fatal
}

// Force a fresh read of config.xml before instantiating models — the script
// runs right after settings/set, so the in-memory config is still the
// pre-save state without this reload.
clearstatcache(true, "/conf/config.xml");
Config::getInstance()->forceReload();

$pluginCfg = new Abuseipdb();
$plugin_enabled = (string)$pluginCfg->general->enabled === "1";
$blacklist_on = (string)$pluginCfg->blacklist->enabled === "1";
$reporter_on = (string)$pluginCfg->reporter->enabled === "1";
$selfcare_on = (string)$pluginCfg->selfcare->enabled === "1";
$permaban_on = (string)$pluginCfg->permaban->enabled === "1";
$suricata_on = (string)$pluginCfg->suricata->enabled === "1";

// Rule-style settings (added in v0.5.0). Defaults preserve pre-v0.5.0
// behaviour when an older config.xml is loaded for the first time.
$requested_style = (string)$pluginCfg->rules->style;
if (!in_array($requested_style, ["classic", "automation", "none"], true)) {
    $requested_style = "classic";
}
$manage_rules = (string)$pluginCfg->rules->manage === "1";
$last_style = (string)$pluginCfg->rules->last_applied_style;

// Effective style: when manage_rules is off the plugin treats every rule
// triplet as "none" — clean up old, create nothing new.
$effective_style = $manage_rules ? $requested_style : "none";

echo "rules: requested_style=$requested_style manage=" . ($manage_rules ? "1" : "0")
    . " last=$last_style effective=$effective_style\n";

// Interface list for the block rule. Accept either internal identifiers
// or friendly GUI names; map everything to the internal identifier.
$block_ifs_raw = (string)$pluginCfg->blacklist->block_interfaces;
$block_ifs_input = array_filter(array_map("trim", explode(",", $block_ifs_raw)));
if (empty($block_ifs_input)) {
    $block_ifs_input = ["wan"];
}

global $config;
$name_to_id = [];
$id_set = [];
foreach (($config["interfaces"] ?? []) as $id => $iface) {
    $id_set[strtolower($id)] = $id;
    $descr = $iface["descr"] ?? strtoupper($id);
    $name_to_id[strtolower($descr)] = $id;
}

$block_ifs = [];
foreach ($block_ifs_input as $name) {
    $key = strtolower($name);
    if (isset($id_set[$key])) {
        $block_ifs[] = $id_set[$key];
    } elseif (isset($name_to_id[$key])) {
        $block_ifs[] = $name_to_id[$key];
    } else {
        echo "WARN: unknown interface '$name' — skipped\n";
    }
}
if (empty($block_ifs)) {
    $block_ifs = ["wan"];
}
$block_ifs = array_values(array_unique($block_ifs));
$block_ifs_csv = implode(",", $block_ifs);
$is_floating = count($block_ifs) > 1;

$alias_name = "abuseipdb_blacklist";
$rule_marker = "[os-abuseipdb] block AbuseIPDB known attackers";
$selfcare_alias_name = "abuseipdb_selfcare";
$selfcare_rule_marker = "[os-abuseipdb] block self-defense list";
$permaban_alias_name = "abuseipdb_permaban";
$permaban_rule_marker = "[os-abuseipdb] block perma-block list";

$dirty_model = false;       // Alias model
$dirty_classic = false;     // legacy <filter><rule>
$dirty_filter = false;      // OPNsense\Firewall\Filter model
$dirty_pluginCfg = false;   // Abuseipdb model (last_applied_style)

// =============================================================
// Aliases (always managed, regardless of rule style)
// =============================================================

$alias_mdl = new Alias();

function ensure_alias($alias_mdl, $name, $description, $want_present, &$dirty_model) {
    $existing = null;
    foreach ($alias_mdl->aliases->alias->iterateItems() as $uuid => $a) {
        if ((string)$a->name === $name) {
            $existing = $a;
            break;
        }
    }
    if ($want_present && $existing === null) {
        $a = $alias_mdl->aliases->alias->Add();
        $a->enabled = "1";
        $a->name = $name;
        // "external" = plugin manages pf-table content itself via pfctl;
        // OPNsense doesn't try to fetch it (unlike urltable which only
        // supports http[s]).
        $a->type = "external";
        // proto is an OptionField with Multiple=Y; "IPv4,IPv6" makes the
        // pf table accept both families, which is required for the IPv6
        // entries the reporter and the manual permaban-add can produce
        // since v0.6.0.
        $a->proto = "IPv4,IPv6";
        $a->counters = "1";
        $a->description = $description;
        $errs = $alias_mdl->performValidation();
        if (count($errs) > 0) {
            foreach ($errs as $e) echo "alias validation: " . $e->getMessage() . "\n";
            exit(1);
        }
        $alias_mdl->serializeToConfig();
        $dirty_model = true;
        echo "alias $name created\n";
    } else if ($existing !== null) {
        // Upgrade-path: pre-0.6.0 installs had proto="IPv4" only. Promote to
        // dual-family so the table can hold IPv6 entries without revoke.
        $cur_proto = (string)$existing->proto;
        if ($cur_proto !== "IPv4,IPv6") {
            $existing->proto = "IPv4,IPv6";
            $alias_mdl->serializeToConfig();
            $dirty_model = true;
            echo "alias $name upgraded proto: '$cur_proto' -> 'IPv4,IPv6'\n";
        } else {
            echo "alias $name exists\n";
        }
    } else {
        echo "alias $name skipped (disabled)\n";
    }
}

ensure_alias($alias_mdl, $alias_name,           "AbuseIPDB blacklist (populated by os-abuseipdb plugin)",   $plugin_enabled && $blacklist_on, $dirty_model);
ensure_alias($alias_mdl, $selfcare_alias_name,  "Self-defense blocklist (populated by os-abuseipdb reporter)", $plugin_enabled && $selfcare_on,  $dirty_model);
ensure_alias($alias_mdl, $permaban_alias_name,  "Perma-block list (populated by os-abuseipdb)",             $plugin_enabled && $permaban_on,  $dirty_model);

// =============================================================
// Block rules — style-aware routing
// =============================================================

// ---- helpers: classic <filter><rule> ----

function classic_normalise(&$config) {
    if (!isset($config["filter"]) || !is_array($config["filter"])) {
        $config["filter"] = [];
    }
    if (!isset($config["filter"]["rule"]) || !is_array($config["filter"]["rule"])) {
        $config["filter"]["rule"] = [];
    }
    if (!empty($config["filter"]["rule"])) {
        $keys = array_keys($config["filter"]["rule"]);
        if (!is_int($keys[0])) {
            // Single-rule deserialisation quirk: wrap into a list.
            $config["filter"]["rule"] = [$config["filter"]["rule"]];
        }
    }
}

function classic_find(&$config, $marker) {
    foreach ($config["filter"]["rule"] as $i => $r) {
        if (is_array($r) && (($r["descr"] ?? "") === $marker)) {
            return $i;
        }
    }
    return null;
}

function classic_remove(&$config, $marker, &$dirty_classic) {
    $idx = classic_find($config, $marker);
    if ($idx !== null) {
        array_splice($config["filter"]["rule"], $idx, 1);
        $dirty_classic = true;
        echo "classic: rule '$marker' removed\n";
        return true;
    }
    return false;
}

function classic_apply(&$config, $marker, $alias, $block_ifs_csv, $is_floating, &$dirty_classic) {
    $idx = classic_find($config, $marker);

    // Interface change forces a delete+recreate (in-place mutation across
    // the floating boundary leaves stale fields).
    if ($idx !== null) {
        $cur_if = $config["filter"]["rule"][$idx]["interface"] ?? "";
        $cur_floating = !empty($config["filter"]["rule"][$idx]["floating"]);
        if ($cur_if !== $block_ifs_csv || $cur_floating !== $is_floating) {
            array_splice($config["filter"]["rule"], $idx, 1);
            $idx = null;
            $dirty_classic = true;
            echo "classic: '$marker' deleted (interface change) — will recreate\n";
        }
    }

    if ($idx === null) {
        // NOTE: leave "protocol" UNSET. <protocol>any</protocol> makes the
        // rule generator emit "proto any" which pf rejects in combination
        // with the auto-generated "{any}" destination macro.
        // ipprotocol="inet46" covers both IPv4 and IPv6 in one rule (OPNsense
        // emits two pf rules under the hood, one per family) — required since
        // v0.6.0 because the source alias is now dual-family.
        $rule = [
            "type"           => "block",
            "interface"      => $block_ifs_csv,
            "ipprotocol"     => "inet46",
            "statetype"      => "keep state",
            "direction"      => "in",
            "quick"          => "1",
            "log"            => "1",
            "disablereplyto" => "1",
            "descr"          => $marker,
            "source"         => ["network" => $alias],
            "destination"    => ["any" => "1"],
            "created"        => ["username" => "os-abuseipdb", "time" => time()],
            "updated"        => ["username" => "os-abuseipdb", "time" => time()],
        ];
        if ($is_floating) {
            $rule["floating"] = "yes";
        }
        // Top of the rule list so attackers are blocked before any user
        // pass rule.
        array_unshift($config["filter"]["rule"], $rule);
        $dirty_classic = true;
        echo "classic: '$marker' created at top\n";
    } else {
        $changed = false;
        if (!empty($config["filter"]["rule"][$idx]["disabled"])) {
            unset($config["filter"]["rule"][$idx]["disabled"]);
            $changed = true;
        }
        if (empty($config["filter"]["rule"][$idx]["disablereplyto"])) {
            $config["filter"]["rule"][$idx]["disablereplyto"] = "1";
            $changed = true;
        }
        if (isset($config["filter"]["rule"][$idx]["protocol"])) {
            unset($config["filter"]["rule"][$idx]["protocol"]);
            $changed = true;
        }
        // v0.6.0 upgrade: promote single-family inet/inet6 rules to inet46.
        $cur_ipp = $config["filter"]["rule"][$idx]["ipprotocol"] ?? "";
        if ($cur_ipp !== "inet46") {
            $config["filter"]["rule"][$idx]["ipprotocol"] = "inet46";
            $changed = true;
        }
        if ($changed) {
            $dirty_classic = true;
            echo "classic: '$marker' updated\n";
        } else {
            echo "classic: '$marker' already up to date\n";
        }
    }
}

// ---- helpers: automation Filter model ----

function automation_find($filter_mdl, $marker) {
    foreach ($filter_mdl->rules->rule->iterateItems() as $uuid => $r) {
        if ((string)$r->description === $marker) {
            return [$uuid, $r];
        }
    }
    return [null, null];
}

function automation_remove($filter_mdl, $marker, &$dirty_filter) {
    [$uuid, $r] = automation_find($filter_mdl, $marker);
    if ($uuid !== null) {
        $filter_mdl->rules->rule->del($uuid);
        $dirty_filter = true;
        echo "automation: rule '$marker' removed\n";
        return true;
    }
    return false;
}

function automation_apply($filter_mdl, $marker, $alias, $block_ifs_csv, &$dirty_filter) {
    [$uuid, $r] = automation_find($filter_mdl, $marker);

    if ($r === null) {
        $r = $filter_mdl->rules->rule->Add();
        $r->enabled = "1";
        $r->action = "block";
        $r->quick = "1";
        $r->interface = $block_ifs_csv;
        $r->direction = "in";
        // inet46 = match IPv4 + IPv6 in the same rule (OPNsense emits two
        // pf rules under the hood). Matches the dual-family alias proto.
        $r->ipprotocol = "inet46";
        // Leave protocol at default "any". The Automation/Filter generator
        // handles this differently to legacy <filter> — "any" is fine here.
        $r->source_net = $alias;
        $r->destination_net = "any";
        $r->disablereplyto = "1";
        $r->log = "1";
        $r->description = $marker;
        // Sequence 1 = top of the list. Multiple plugin rules with seq=1
        // are tolerated; their relative order is then by add-order.
        $r->sequence = "1";
        $dirty_filter = true;
        echo "automation: '$marker' created\n";
    } else {
        $changed = false;
        $want = [
            "enabled"        => "1",
            "action"         => "block",
            "quick"          => "1",
            "interface"      => $block_ifs_csv,
            "direction"      => "in",
            "ipprotocol"     => "inet46",
            "source_net"     => $alias,
            "destination_net"=> "any",
            "disablereplyto" => "1",
            "log"            => "1",
        ];
        foreach ($want as $k => $v) {
            $cur = (string)$r->$k;
            if ($cur !== $v) {
                $r->$k = $v;
                $changed = true;
            }
        }
        if ($changed) {
            $dirty_filter = true;
            echo "automation: '$marker' updated\n";
        } else {
            echo "automation: '$marker' already up to date\n";
        }
    }
}

// ---- generic style-aware ensure ----
//
// Each rule triplet is described by:
//   $marker     : description string used for idempotent lookup
//   $alias      : alias name used as block source
//   $want       : whether the rule should be present in the current
//                 effective style (plugin+type enabled AND manage AND
//                 effective != 'none')
//
// Cleanup happens unconditionally based on $last_style/$effective_style
// transitions so stale rules from previous styles get removed.

classic_normalise($config);
$filter_mdl = new FwFilter();

function ensure_rule($marker, $alias, $want, $effective_style, $last_style,
                     $block_ifs_csv, $is_floating,
                     &$config, $filter_mdl,
                     &$dirty_classic, &$dirty_filter) {

    // 1) Cleanup in the *previous* style if it's different from where
    //    we want the rule to live now (or where we want NO rule).
    if ($last_style !== "" && $last_style !== $effective_style) {
        if ($last_style === "classic") {
            classic_remove($config, $marker, $dirty_classic);
        } else if ($last_style === "automation") {
            automation_remove($filter_mdl, $marker, $dirty_filter);
        }
    }

    // 2) If the rule should not be present at all, also clean up in the
    //    *current* effective style (covers the case last==current==none
    //    after a previous run already cleaned, plus the case where the
    //    type-specific toggle was just disabled).
    if (!$want) {
        if ($effective_style === "classic") {
            classic_remove($config, $marker, $dirty_classic);
        } else if ($effective_style === "automation") {
            automation_remove($filter_mdl, $marker, $dirty_filter);
        }
        // else: effective=none, nothing to remove in 'none'.
        return;
    }

    // 3) Apply in the current effective style.
    if ($effective_style === "classic") {
        classic_apply($config, $marker, $alias, $block_ifs_csv, $is_floating, $dirty_classic);
    } else if ($effective_style === "automation") {
        automation_apply($filter_mdl, $marker, $alias, $block_ifs_csv, $dirty_filter);
    }
    // else: effective=none, no apply.
}

ensure_rule(
    $rule_marker, $alias_name,
    $plugin_enabled && $blacklist_on,
    $effective_style, $last_style,
    $block_ifs_csv, $is_floating,
    $config, $filter_mdl,
    $dirty_classic, $dirty_filter
);
ensure_rule(
    $selfcare_rule_marker, $selfcare_alias_name,
    $plugin_enabled && $selfcare_on,
    $effective_style, $last_style,
    $block_ifs_csv, $is_floating,
    $config, $filter_mdl,
    $dirty_classic, $dirty_filter
);
ensure_rule(
    $permaban_rule_marker, $permaban_alias_name,
    $plugin_enabled && $permaban_on,
    $effective_style, $last_style,
    $block_ifs_csv, $is_floating,
    $config, $filter_mdl,
    $dirty_classic, $dirty_filter
);

// Persist the new "last applied style" if it actually changed.
if ($last_style !== $effective_style) {
    $pluginCfg->rules->last_applied_style = $effective_style;
    $dirty_pluginCfg = true;
    echo "rules: last_applied_style $last_style → $effective_style\n";
}

// =============================================================
// Cron jobs (independent of rule style)
// =============================================================

$cron_mdl = new Cron();
$dirty_cron = false;

function find_cron_job($mdl, $descr) {
    foreach ($mdl->jobs->job->iterateItems() as $uuid => $j) {
        if ((string)$j->description === $descr) return [$uuid, $j];
    }
    return [null, null];
}

function ensure_cron($mdl, $descr, $command, $m, $h, $desired_enabled) {
    [$uuid, $j] = find_cron_job($mdl, $descr);
    $changed = false;
    if ($j === null) {
        if ($desired_enabled) {
            $n = $mdl->jobs->job->Add();
            $n->origin = "abuseipdb";
            $n->enabled = "1";
            $n->minutes = $m;
            $n->hours = $h;
            $n->days = "*";
            $n->months = "*";
            $n->weekdays = "*";
            $n->who = "root";
            $n->command = $command;
            $n->description = $descr;
            $changed = true;
            echo "cron '$descr' created\n";
        }
    } else {
        $want = $desired_enabled ? "1" : "0";
        if ((string)$j->enabled !== $want) {
            $j->enabled = $want;
            $changed = true;
            echo "cron '$descr' " . ($desired_enabled ? "re-enabled" : "disabled") . "\n";
        }
    }
    return $changed;
}

$dirty_cron |= ensure_cron(
    $cron_mdl,
    "os-abuseipdb: daily blacklist download",
    "abuseipdb download",
    "13", "3",
    $plugin_enabled && $blacklist_on
);
$dirty_cron |= ensure_cron(
    $cron_mdl,
    "os-abuseipdb: reporter run",
    "abuseipdb report",
    "*/5", "*",
    $plugin_enabled && $reporter_on
);
$dirty_cron |= ensure_cron(
    $cron_mdl,
    "os-abuseipdb: suricata reporter run",
    "abuseipdb suricata",
    "*/5", "*",
    $plugin_enabled && $suricata_on
);
$dirty_cron |= ensure_cron(
    $cron_mdl,
    "os-abuseipdb: self-defense cleanup",
    "abuseipdb selfcare_cleanup",
    "7", "*",
    $plugin_enabled && $selfcare_on
);
$dirty_cron |= ensure_cron(
    $cron_mdl,
    "os-abuseipdb: perma-block auto-promote scan",
    "abuseipdb permaban_scan",
    "23", "3",
    $plugin_enabled && $permaban_on
);
$dirty_cron |= ensure_cron(
    $cron_mdl,
    "os-abuseipdb: perma-block hit counter sampler",
    "abuseipdb permaban_count",
    "*/5", "*",
    $plugin_enabled && $permaban_on
);

if ($dirty_cron) {
    $errs = $cron_mdl->performValidation();
    if (count($errs) > 0) {
        foreach ($errs as $e) echo "cron validation: " . $e->getMessage() . "\n";
        exit(1);
    }
}

// =============================================================
// Save phase
// =============================================================
//
// write_config() rebuilds the SimpleXML tree from the legacy $config
// array and wipes any model changes we made earlier via
// $mdl->serializeToConfig(). Save order:
//   1) write classic $config first (if classic is dirty)
//   2) re-serialize all model trees
//   3) Config::save() commits the final tree to disk
//
// Validate the Filter model before serialising — the Automation/Filter
// generator is strict about field combinations.

if ($dirty_filter) {
    $errs = $filter_mdl->performValidation();
    if (count($errs) > 0) {
        foreach ($errs as $e) echo "filter validation: " . $e->getMessage() . "\n";
        exit(1);
    }
}

if ($dirty_classic) {
    write_config("os-abuseipdb: classic filter rule");
    echo "classic config saved\n";
}

if ($dirty_model) {
    $alias_mdl->serializeToConfig();
}
if ($dirty_filter) {
    $filter_mdl->serializeToConfig();
}
if ($dirty_cron) {
    $cron_mdl->serializeToConfig();
}
if ($dirty_pluginCfg) {
    $pluginCfg->serializeToConfig();
}

if ($dirty_model || $dirty_filter || $dirty_cron || $dirty_pluginCfg) {
    Config::getInstance()->save();
    echo "model config saved\n";
}

if ($dirty_cron) {
    // Correct action name is 'restart' (not 'reload') — regenerates
    // /var/cron/tabs/nobody and restarts the daemon.
    shell_exec("/usr/local/sbin/configctl cron restart");
}

if (!$dirty_model && !$dirty_classic && !$dirty_filter && !$dirty_cron && !$dirty_pluginCfg) {
    echo "no changes\n";
}
