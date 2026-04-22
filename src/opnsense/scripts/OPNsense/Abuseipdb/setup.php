<?php
/*
 * Create/update the abuseipdb_blacklist alias and a WAN block rule via the
 * official OPNsense MVC model API — this ensures validation runs and the
 * config is persisted the way the GUI would persist it.
 *
 * Copyright (c) 2026 Kai Schlestein
 * BSD 2-Clause.
 */

require_once("config.inc");
require_once("util.inc");

use OPNsense\Core\Config;
use OPNsense\Firewall\Alias;
use OPNsense\Firewall\Filter;
use OPNsense\Abuseipdb\Abuseipdb;

$pluginCfg = new Abuseipdb();
$plugin_enabled = (string)$pluginCfg->general->enabled === "1";
$blacklist_on = (string)$pluginCfg->blacklist->enabled === "1";

$alias_name = "abuseipdb_blacklist";
$rule_marker = "os-abuseipdb block rule";
$dirty = false;

// --- Alias ---
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
    $a->type = "urltable";
    $a->proto = "IPv4";
    $a->counters = "1";
    $a->updatefreq = "0.04167"; // ~ 1h
    $a->content = "file:///var/db/abuseipdb/blocklist.txt";
    $a->description = "AbuseIPDB blacklist (managed by os-abuseipdb plugin)";

    $errs = $alias_mdl->performValidation();
    if (count($errs) > 0) {
        foreach ($errs as $e) echo "alias validation error: " . $e->getMessage() . "\n";
        exit(1);
    }
    $alias_mdl->serializeToConfig();
    $dirty = true;
    echo "alias $alias_name created\n";
} else if ($existing_alias !== null) {
    echo "alias $alias_name exists\n";
} else {
    echo "alias skipped (plugin/blacklist disabled)\n";
}

// --- Filter rule on WAN ---
$filter_mdl = new Filter();
$existing_rule = null;
foreach ($filter_mdl->rules->rule->iterateItems() as $uuid => $r) {
    if ((string)$r->description === $rule_marker) {
        $existing_rule = $r;
        break;
    }
}

if ($plugin_enabled && $blacklist_on) {
    if ($existing_rule === null) {
        $r = $filter_mdl->rules->rule->Add();
        $r->enabled = "1";
        $r->sequence = "1";
        $r->action = "block";
        $r->quick = "1";
        $r->interface = "wan";
        $r->direction = "in";
        $r->ipprotocol = "inet";
        $r->protocol = "any";
        $r->source_net = $alias_name;
        $r->destination_net = "any";
        $r->description = $rule_marker;
        $r->log = "1";

        $errs = $filter_mdl->performValidation();
        if (count($errs) > 0) {
            foreach ($errs as $e) echo "rule validation error: " . $e->getMessage() . "\n";
            exit(1);
        }
        $filter_mdl->serializeToConfig();
        $dirty = true;
        echo "WAN block rule created\n";
    } else {
        if ((string)$existing_rule->enabled !== "1") {
            $existing_rule->enabled = "1";
            $filter_mdl->serializeToConfig();
            $dirty = true;
            echo "WAN block rule re-enabled\n";
        } else {
            echo "WAN block rule exists\n";
        }
    }
} else if ($existing_rule !== null) {
    if ((string)$existing_rule->enabled !== "0") {
        $existing_rule->enabled = "0";
        $filter_mdl->serializeToConfig();
        $dirty = true;
        echo "WAN block rule disabled\n";
    }
}

if ($dirty) {
    Config::getInstance()->save();
    echo "config saved\n";
} else {
    echo "no changes\n";
}
