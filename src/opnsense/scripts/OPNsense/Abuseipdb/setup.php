<?php
/*
 * Ensure firewall alias + WAN block rule for os-abuseipdb exist.
 * Alias goes into the modern OPNsense\Firewall\Alias model,
 * the block rule goes into the classic <filter><rule> list so it shows up
 * in the traditional "Firewall → Rules → WAN" tab where admins edit rules.
 *
 * Copyright (c) 2026 Kai Schlestein
 * BSD 2-Clause.
 */

require_once("config.inc");
require_once("util.inc");

use OPNsense\Core\Config;
use OPNsense\Firewall\Alias;
use OPNsense\Cron\Cron;
use OPNsense\Abuseipdb\Abuseipdb;

$pluginCfg = new Abuseipdb();
$plugin_enabled = (string)$pluginCfg->general->enabled === "1";
$blacklist_on = (string)$pluginCfg->blacklist->enabled === "1";
$reporter_on = (string)$pluginCfg->reporter->enabled === "1";

$alias_name = "abuseipdb_blacklist";
$rule_marker = "[os-abuseipdb] block AbuseIPDB known attackers";

$dirty_model = false;

// --- Alias (modern model) ---
$alias_mdl = new Alias();
$existing_alias = null;
foreach ($alias_mdl->aliases->alias->iterateItems() as $uuid => $a) {
    if ((string)$a->name === $alias_name) {
        $existing_alias = $a;
        break;
    }
}

if ($plugin_enabled && $blacklist_on && $existing_alias === null) {
    $a = $alias_mdl->aliases->alias->Add();
    $a->enabled = "1";
    $a->name = $alias_name;
    // "external" = plugin manages pf-table content itself via pfctl,
    // OPNsense doesn't try to fetch it (unlike urltable which only supports http[s]).
    $a->type = "external";
    $a->proto = "IPv4";
    $a->counters = "1";
    $a->description = "AbuseIPDB blacklist (populated by os-abuseipdb plugin)";
    $errs = $alias_mdl->performValidation();
    if (count($errs) > 0) {
        foreach ($errs as $e) echo "alias validation: " . $e->getMessage() . "\n";
        exit(1);
    }
    $alias_mdl->serializeToConfig();
    $dirty_model = true;
    echo "alias $alias_name created\n";
} else if ($existing_alias !== null) {
    echo "alias $alias_name exists\n";
} else {
    echo "alias skipped (plugin/blacklist disabled)\n";
}

// --- Block rule (classic <filter><rule>) ---
global $config;
if (!isset($config["filter"])) $config["filter"] = [];
if (!isset($config["filter"]["rule"]) || !is_array($config["filter"]["rule"])) {
    $config["filter"]["rule"] = [];
}

$rule_idx = null;
foreach ($config["filter"]["rule"] as $i => $r) {
    if (is_array($r) && (($r["descr"] ?? "") === $rule_marker)) {
        $rule_idx = $i;
        break;
    }
}

$dirty_classic = false;

if ($plugin_enabled && $blacklist_on) {
    $rule = [
        "type"           => "block",
        "interface"      => "wan",
        "ipprotocol"     => "inet",
        "statetype"      => "keep state",
        "direction"      => "in",
        "quick"          => "1",
        "log"            => "1",
        "disablereplyto" => "1",  // pf rejects reply-to on block rules (esp. on pppoe WAN)
        "descr"          => $rule_marker,
        "source"         => ["network" => $alias_name],
        "destination"    => ["any" => "1"],
        "protocol"       => "any",
        "created"        => ["username" => "os-abuseipdb", "time" => time()],
        "updated"        => ["username" => "os-abuseipdb", "time" => time()],
    ];
    if ($rule_idx === null) {
        // Put it near the top so it blocks before any user pass rule on WAN
        array_unshift($config["filter"]["rule"], $rule);
        $dirty_classic = true;
        echo "WAN block rule inserted at top of user rules\n";
    } else {
        // already present — ensure it isn't disabled and has disablereplyto
        if (!empty($config["filter"]["rule"][$rule_idx]["disabled"])) {
            unset($config["filter"]["rule"][$rule_idx]["disabled"]);
            $dirty_classic = true;
            echo "WAN block rule re-enabled\n";
        }
        if (empty($config["filter"]["rule"][$rule_idx]["disablereplyto"])) {
            $config["filter"]["rule"][$rule_idx]["disablereplyto"] = "1";
            $dirty_classic = true;
            echo "WAN block rule: disablereplyto migrated\n";
        }
        if (!$dirty_classic) {
            echo "WAN block rule exists\n";
        }
    }
} else if ($rule_idx !== null) {
    // plugin disabled → mark rule as disabled (don't delete — user may want to keep)
    if (empty($config["filter"]["rule"][$rule_idx]["disabled"])) {
        $config["filter"]["rule"][$rule_idx]["disabled"] = "1";
        $dirty_classic = true;
        echo "WAN block rule disabled\n";
    }
}

// --- Cron jobs ---
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

// Download once per day at 03:13 (off-peak, avoid :00/:30)
$dirty_cron |= ensure_cron(
    $cron_mdl,
    "os-abuseipdb: daily blacklist download",
    "abuseipdb download",
    "13", "3",
    $plugin_enabled && $blacklist_on
);

// Reporter every 5 minutes
$dirty_cron |= ensure_cron(
    $cron_mdl,
    "os-abuseipdb: reporter run",
    "abuseipdb report",
    "*/5", "*",
    $plugin_enabled && $reporter_on
);

if ($dirty_cron) {
    $errs = $cron_mdl->performValidation();
    if (count($errs) > 0) {
        foreach ($errs as $e) echo "cron validation: " . $e->getMessage() . "\n";
        exit(1);
    }
    $cron_mdl->serializeToConfig();
}

// Two-phase save: write_config() on legacy $config, then Config::save() on model tree.
// Doing both in one pass loses model changes because write_config rewrites the tree
// from the stale $config array.
if ($dirty_classic) {
    write_config("os-abuseipdb: classic WAN user rule");
    echo "classic config saved\n";
}
if ($dirty_model || $dirty_cron) {
    Config::getInstance()->save();
    echo "model config saved\n";
}
if ($dirty_cron) {
    // Correct action name is 'restart' (not 'reload') — regenerates
    // /var/cron/tabs/nobody from the cron template and restarts the daemon.
    shell_exec("/usr/local/sbin/configctl cron restart");
}
if (!$dirty_model && !$dirty_classic && !$dirty_cron) {
    echo "no changes\n";
}
