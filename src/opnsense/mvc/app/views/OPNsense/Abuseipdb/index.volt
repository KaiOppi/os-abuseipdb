{#
 # Copyright (c) 2026 Kai Schlestein
 # BSD 2-Clause.
 #}

<style>
    .abuseipdb-info { background: #f4f8fb; border: 1px solid #d1dde6; padding: 10px 14px; margin-bottom: 12px; border-radius: 3px; }
    .abuseipdb-info h4 { margin: 0 0 8px 0; font-size: 13px; }
    .abuseipdb-info table { width: 100%; font-size: 12px; }
    .abuseipdb-info td { padding: 2px 8px 2px 0; }
    .abuseipdb-info td.lbl { color: #555; width: 180px; white-space: nowrap; }
    .abuseipdb-info .ok { color: #2e7d32; font-weight: 600; }
    .abuseipdb-info .warn { color: #c62828; font-weight: 600; }
    #reportsTable, #selfcareTable, #permabanTable { width: 100%; font-size: 12px; }
    #reportsTable td, #reportsTable th,
    #selfcareTable td, #selfcareTable th,
    #permabanTable td, #permabanTable th { padding: 4px 8px; border-bottom: 1px solid #eee; }
    #reportsTable th, #selfcareTable th, #permabanTable th { background: #f4f4f4; text-align: left; }
</style>

<script>
    function fmtTs(ts) {
        if (!ts) return '—';
        var d = new Date(ts * 1000);
        return d.toLocaleString();
    }

    function refreshStats() {
        ajaxCall(
            url = "/api/abuseipdb/service/stats",
            sendData = {},
            callback = function(resp) {
                if (!resp || resp.status !== 'ok') return;
                var d = resp.data;
                ifaceDescr = d.iface_descr || {};
                $("#stat_bl_count").text(d.blocklist_ips.toLocaleString());
                $("#stat_bl_last").text(fmtTs(d.blocklist_last_update));
                $("#stat_last_run").text(fmtTs(d.last_run));
                $("#stat_last_ok").text(d.last_run_ok === null ? '—' : (d.last_run_ok ? 'OK' : 'failed'))
                                   .toggleClass('ok', d.last_run_ok === true)
                                   .toggleClass('warn', d.last_run_ok === false);
                $("#stat_quota").text(d.quota_remaining === null ? '—' : d.quota_remaining);
                $("#stat_reports_today").text(d.reports_today);
                $("#stat_reports_total").text(d.reports_total);
                $("#stat_selfcare_active").text((d.selfcare_active || 0).toLocaleString());
                $("#stat_selfcare_total").text((d.selfcare_total || 0).toLocaleString());
                $("#stat_permaban_count").text((d.permaban_count || 0).toLocaleString());
                renderStatsTab(d);
            }
        );
    }

    function renderIfaceTable(targetSel, dict) {
        var $t = $(targetSel).empty();
        var keys = Object.keys(dict || {}).sort(function(a,b){ return (dict[b]||0) - (dict[a]||0); });
        if (keys.length === 0) {
            $t.append('<tr><td colspan="2" style="color:#888;padding:6px">—</td></tr>');
            return;
        }
        var max = Math.max.apply(null, keys.map(function(k){ return dict[k]; }));
        keys.forEach(function(k) {
            var pct = max > 0 ? Math.round(dict[k] / max * 100) : 0;
            var label = ifaceDescr[k] || k;
            $t.append(
                '<tr>' +
                '<td style="white-space:nowrap;padding-right:8px"><b>' + label + '</b> <span style="color:#888;font-size:11px">' + k + '</span></td>' +
                '<td style="width:100%">' +
                '<div style="background:#3498db;color:#fff;padding:2px 6px;width:' + Math.max(pct, 5) + '%;min-width:30px;font-size:11px">' + dict[k].toLocaleString() + '</div>' +
                '</td></tr>'
            );
        });
    }

    function renderDailyChart(targetSel, series) {
        var $t = $(targetSel).empty();
        if (!series || series.length === 0) {
            $t.append('<tr><td style="color:#888">—</td></tr>');
            return;
        }
        var max = Math.max.apply(null, series.map(function(p){ return p.count; }));
        series.forEach(function(p) {
            var pct = max > 0 ? Math.round(p.count / max * 100) : 0;
            var d = new Date(p.day);
            var dayLbl = d.toLocaleDateString(undefined, {weekday:'short', day:'2-digit', month:'2-digit'});
            $t.append(
                '<tr>' +
                '<td style="white-space:nowrap;padding-right:8px;font-size:11px">' + dayLbl + '</td>' +
                '<td style="width:100%">' +
                '<div style="background:#27ae60;color:#fff;padding:2px 6px;width:' + Math.max(pct, 1) + '%;min-width:30px;font-size:11px">' + p.count.toLocaleString() + '</div>' +
                '</td></tr>'
            );
        });
    }

    function renderStatsTab(d) {
        renderIfaceTable("#stats_iface_sc_active tbody", d.by_iface ? d.by_iface.selfcare_active : {});
        renderIfaceTable("#stats_iface_sc_total tbody",  d.by_iface ? d.by_iface.selfcare_total  : {});
        renderIfaceTable("#stats_iface_rep_today tbody", d.by_iface ? d.by_iface.reports_today   : {});
        renderIfaceTable("#stats_iface_rep_total tbody", d.by_iface ? d.by_iface.reports_total   : {});
        renderDailyChart("#stats_daily_reports tbody",   d.daily ? d.daily.reports         : []);
        renderDailyChart("#stats_daily_selfcare tbody",  d.daily ? d.daily.selfcare_added  : []);
    }

    function fmtDuration(sec) {
        sec = Math.max(0, sec|0);
        var d = Math.floor(sec / 86400);
        var h = Math.floor((sec % 86400) / 3600);
        var m = Math.floor((sec % 3600) / 60);
        if (d > 0) return d + 'd ' + h + 'h';
        if (h > 0) return h + 'h ' + m + 'm';
        return m + 'm';
    }

    // identifier → friendly description, populated by refreshStats.
    var ifaceDescr = {};
    function fmtIface(csv) {
        if (!csv) return '—';
        return csv.split(',').map(function(s){
            s = s.trim(); if (!s) return '';
            return ifaceDescr[s] || s;
        }).filter(Boolean).join(', ');
    }

    function refreshSelfcare() {
        ajaxCall(
            url = "/api/abuseipdb/service/selfcare_list",
            sendData = {limit: 200},
            callback = function(resp) {
                if (!resp || resp.status !== 'ok') return;
                var rows = resp.data.rows;
                var total = resp.data.total_active;
                $("#selfcareTotal").text(total);
                var tbody = $("#selfcareTable tbody").empty();
                if (rows.length === 0) {
                    tbody.append('<tr><td colspan="6" style="text-align:center;color:#888;padding:12px">{{ lang._("No active entries.") }}</td></tr>');
                } else {
                    rows.forEach(function(r) {
                        var $tr = $('<tr>');
                        $tr.append($('<td>').append($('<tt>').text(r.ip)));
                        $tr.append($('<td>').text(fmtIface(r.iface)));
                        $tr.append($('<td>').text(fmtTs(r.added_ts)));
                        $tr.append($('<td>').text(fmtTs(r.expires_ts) + ' (' + fmtDuration(r.remaining_sec) + ')'));
                        $tr.append($('<td>').text(r.categories || ''));
                        var $btn = $('<button class="btn btn-xs btn-warning promoteBtn" title="Promote to Perma-Block"><span class="fa fa-bolt"></span> Permaban</button>');
                        $btn.attr('data-ip', r.ip);
                        $tr.append($('<td>').append($btn));
                        tbody.append($tr);
                    });
                }
            }
        );
    }

    function refreshPermaban() {
        ajaxCall(
            url = "/api/abuseipdb/service/permaban_list",
            sendData = {limit: 500},
            callback = function(resp) {
                if (!resp || resp.status !== 'ok') return;
                var rows = resp.data.rows;
                $("#permabanTotal").text(resp.data.total);
                var tbody = $("#permabanTable tbody").empty();
                if (rows.length === 0) {
                    tbody.append('<tr><td colspan="5" style="text-align:center;color:#888;padding:12px">{{ lang._("No Perma-Block entries.") }}</td></tr>');
                } else {
                    rows.forEach(function(r) {
                        var $tr = $('<tr>');
                        $tr.append($('<td>').append($('<tt>').text(r.ip)));
                        $tr.append($('<td>').text(fmtTs(r.added_ts)));
                        $tr.append($('<td>').text(r.source || ''));
                        $tr.append($('<td>').text(r.note || ''));
                        var $rm = $('<button class="btn btn-xs btn-default removePermabanBtn" title="Remove from Perma-Block"><span class="fa fa-trash"></span> Remove</button>');
                        $rm.attr('data-ip', r.ip);
                        $tr.append($('<td>').append($rm));
                        tbody.append($tr);
                    });
                }
            }
        );
    }

    function refreshReports() {
        ajaxCall(
            url = "/api/abuseipdb/service/reports",
            sendData = {limit: 100},
            callback = function(resp) {
                if (!resp || resp.status !== 'ok') return;
                var rows = resp.data.rows;
                var tbody = $("#reportsTable tbody").empty();
                if (rows.length === 0) {
                    tbody.append('<tr><td colspan="6" style="text-align:center;color:#888;padding:12px">{{ lang._("No reports yet.") }}</td></tr>');
                } else {
                    rows.forEach(function(r) {
                        // Build the row with jQuery objects so .text(...) escapes
                        // user-provided strings safely AND renders them as plain
                        // text. Earlier we used .html(div.text(s).html()) which
                        // round-tripped < / > / & through HTML entities and could
                        // leave them visible as `&lt;` in some browsers.
                        var $tr = $('<tr>');
                        $tr.append($('<td>').text(fmtTs(r.ts)));
                        $tr.append($('<td>').append($('<tt>').text(r.ip)));
                        $tr.append($('<td>').text(fmtIface(r.iface)));
                        $tr.append($('<td>').text(r.categories || ''));
                        $tr.append($('<td>').addClass(r.ok ? 'ok' : 'warn').text(r.ok ? 'OK' : 'failed'));
                        $tr.append($('<td>').text(r.message || ''));
                        tbody.append($tr);
                    });
                }
                $("#reportsLastFetch").text("{{ lang._('last fetched:') }} " + new Date().toLocaleTimeString());
            }
        );
    }

    $(document).ready(function() {
        var data_get_map = {'frm_general': "/api/abuseipdb/settings/get",
                            'frm_blacklist': "/api/abuseipdb/settings/get",
                            'frm_reporter': "/api/abuseipdb/settings/get",
                            'frm_selfcare': "/api/abuseipdb/settings/get",
                            'frm_permaban': "/api/abuseipdb/settings/get"};

        mapDataToFormUI(data_get_map).done(function(){
            updateServiceControlUI('abuseipdb');
            var val = ($("#abuseipdb\\.blacklist\\.block_interfaces").val() || "wan").trim() || "wan";
            var parts = val.split(",").map(function(s){return s.trim();}).filter(Boolean);
            $("#jumpToRule").attr("href",
                parts.length > 1 ? "/ui/firewall/filter#floating"
                                 : "/ui/firewall/filter#" + (parts[0] || "wan"));
        });

        function saveAll() {
            // Save all four forms in ONE request. Previously we chained
            // four saveFormToEndpoint calls; if the user hit Save before
            // every tab's form had finished hydrating via mapDataToFormUI,
            // the first call could ship stale defaults (e.g. selfcare.enabled=0
            // while the checkbox was actually ticked), and setup.php then saw
            // "disabled" and skipped the alias. One call = no partial ordering,
            // no stale snapshots.
            saveFormToEndpoint(
                url = "/api/abuseipdb/settings/set",
                formid = 'frm_all',
                callback_ok = function(){
                    ajaxCall(
                        url = "/api/abuseipdb/service/setup",
                        sendData = {},
                        callback = function(resp){
                            var out = (resp && resp.output) ? resp.output : "";
                            $("#responseMsg").removeClass("hidden").html(
                                "{{ lang._('Saved and firewall updated:') }}<br><pre>" + out + "</pre>"
                            );
                            refreshStats();
                        }
                    );
                }
            );
        }
        $("#saveAct").click(saveAll);

        $("#testConnectionAct").click(function(){
            ajaxCall(
                url = "/api/abuseipdb/service/test_connection",
                sendData = {},
                callback = function(data){
                    $("#responseMsg").removeClass("hidden").html(
                        "{{ lang._('Test result:') }} " + (data.output || data.message)
                    );
                }
            );
        });

        $("#downloadNowAct").click(function(){
            ajaxCall(
                url = "/api/abuseipdb/service/download",
                sendData = {},
                callback = function(data){
                    $("#responseMsg").removeClass("hidden").html(
                        "{{ lang._('Download:') }} " + (data.output || data.message)
                    );
                    refreshStats();
                }
            );
        });

        $('a[data-toggle="tab"]').on('shown.bs.tab', function(e) {
            var href = $(e.target).attr('href');
            if (href === '#logtab') refreshReports();
            if (href === '#selfcare') refreshSelfcare();
            if (href === '#permaban') refreshPermaban();
            if (href === '#statstab') refreshStats();
        });
        $("#refreshReportsAct").click(refreshReports);
        $("#refreshSelfcareAct").click(refreshSelfcare);
        $("#refreshPermabanAct").click(refreshPermaban);

        // "→ Permaban" button on each row of the self-defense list.
        $("#selfcareTable").on("click", ".promoteBtn", function() {
            var ip = $(this).attr("data-ip");
            if (!ip) return;
            if (!confirm("{{ lang._('Permanently block ') }}" + ip + "?\n\n" +
                         "{{ lang._('Perma-Block stays in place until you remove it manually.') }}")) {
                return;
            }
            ajaxCall(
                url = "/api/abuseipdb/service/permaban_add",
                sendData = {ip: ip, note: "manual from selfcare list"},
                callback = function(resp) {
                    refreshSelfcare();
                    refreshPermaban();
                    refreshStats();
                }
            );
        });

        // Add button on Permaban tab.
        $("#permabanAddAct").click(function() {
            var ip = ($("#permaban_new_ip").val() || "").trim();
            var note = ($("#permaban_new_note").val() || "").trim();
            if (!ip) { alert("{{ lang._('Enter an IP address.') }}"); return; }
            ajaxCall(
                url = "/api/abuseipdb/service/permaban_add",
                sendData = {ip: ip, note: note},
                callback = function(resp) {
                    if (resp && resp.status === 'ok') {
                        $("#permaban_new_ip").val("");
                        $("#permaban_new_note").val("");
                        refreshPermaban();
                        refreshStats();
                    } else {
                        alert((resp && resp.message) || "{{ lang._('Add failed') }}");
                    }
                }
            );
        });

        // Remove button on each row of the Perma-Block list.
        $("#permabanTable").on("click", ".removePermabanBtn", function() {
            var ip = $(this).attr("data-ip");
            if (!ip) return;
            if (!confirm("{{ lang._('Remove ') }}" + ip + " {{ lang._('from Perma-Block?') }}")) return;
            ajaxCall(
                url = "/api/abuseipdb/service/permaban_remove",
                sendData = {ip: ip},
                callback = function(resp) {
                    refreshPermaban();
                    refreshStats();
                }
            );
        });

        // Manual scan trigger on Permaban tab.
        $("#permabanScanAct").click(function() {
            ajaxCall(
                url = "/api/abuseipdb/service/permaban_promote",
                sendData = {},
                callback = function(resp) {
                    var n = (resp && resp.promoted) || 0;
                    $("#responseMsg").removeClass("hidden").html(
                        "{{ lang._('Auto-promote scan:') }} " + n + " " + "{{ lang._('IP(s) promoted.') }}"
                    );
                    refreshPermaban();
                    refreshStats();
                }
            );
        });

        refreshStats();
        setInterval(refreshStats, 30000);
    });
</script>

<div class="abuseipdb-info">
    <h4>{{ lang._('AbuseIPDB Status') }}</h4>
    <table>
        <tr>
            <td class="lbl">{{ lang._('Data source') }}</td>
            <td><tt>https://api.abuseipdb.com/api/v2/blacklist</tt></td>
        </tr>
        <tr>
            <td class="lbl">{{ lang._('Blocklist IPs in pf table') }}</td>
            <td><span id="stat_bl_count">—</span></td>
        </tr>
        <tr>
            <td class="lbl">{{ lang._('Last download') }}</td>
            <td><span id="stat_bl_last">—</span> (<span id="stat_last_ok">—</span>)</td>
        </tr>
        <tr>
            <td class="lbl">{{ lang._('API quota remaining') }}</td>
            <td><span id="stat_quota">—</span></td>
        </tr>
        <tr>
            <td class="lbl">{{ lang._('Reports today / total') }}</td>
            <td><span id="stat_reports_today">—</span> / <span id="stat_reports_total">—</span></td>
        </tr>
        <tr>
            <td class="lbl">{{ lang._('Self-defense (active / total)') }}</td>
            <td><span id="stat_selfcare_active">—</span> / <span id="stat_selfcare_total">—</span></td>
        </tr>
        <tr>
            <td class="lbl">{{ lang._('Perma-Block entries') }}</td>
            <td><span id="stat_permaban_count">—</span></td>
        </tr>
    </table>
    <div style="margin-top:8px">
        <b>{{ lang._('Jump to:') }}</b>
        <a href="/ui/firewall/alias#abuseipdb_blacklist" class="btn btn-default btn-xs">
            <span class="fa fa-arrow-right"></span> {{ lang._('Alias') }}
        </a>
        <a id="jumpToRule" href="/ui/firewall/filter" class="btn btn-default btn-xs">
            <span class="fa fa-arrow-right"></span> {{ lang._('Block rule') }}
        </a>
        <a href="/ui/cron" class="btn btn-default btn-xs">
            <span class="fa fa-arrow-right"></span> {{ lang._('Cron jobs') }}
        </a>
        <a href="/ui/diagnostics/log/core/filter" class="btn btn-default btn-xs">
            <span class="fa fa-arrow-right"></span> {{ lang._('Firewall log') }}
        </a>
    </div>
</div>

<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#general">{{ lang._('General') }}</a></li>
    <li><a data-toggle="tab" href="#blacklist">{{ lang._('Blacklist') }}</a></li>
    <li><a data-toggle="tab" href="#reporter">{{ lang._('Reporter') }}</a></li>
    <li><a data-toggle="tab" href="#selfcare">{{ lang._('Self-Defense') }}</a></li>
    <li><a data-toggle="tab" href="#permaban">{{ lang._('Perma-Block') }}</a></li>
    <li><a data-toggle="tab" href="#logtab">{{ lang._('Log') }}</a></li>
    <li><a data-toggle="tab" href="#statstab">{{ lang._('Statistics') }}</a></li>
</ul>

<div id="frm_all" class="tab-content content-box">
    {# id="frm_all" is here (not on an inner wrapper) because Bootstrap
       uses the direct-child selector `.tab-content > .tab-pane` to show
       exactly one pane at a time. Nesting an extra div broke that and
       every tab was rendered stacked. saveFormToEndpoint walks the full
       subtree for fields, so putting the id one level up still captures
       every model-path-tagged input in a single POST. #}
    <div id="general" class="tab-pane fade in active">
        {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general']) }}
    </div>
    <div id="blacklist" class="tab-pane fade">
        {{ partial("layout_partials/base_form", ['fields': blacklistForm, 'id': 'frm_blacklist']) }}
    </div>
    <div id="reporter" class="tab-pane fade">
        {{ partial("layout_partials/base_form", ['fields': reporterForm, 'id': 'frm_reporter']) }}
    </div>
    <div id="selfcare" class="tab-pane fade">
        {{ partial("layout_partials/base_form", ['fields': selfcareForm, 'id': 'frm_selfcare']) }}
        <div style="padding:10px 15px 15px 15px">
            <h4 style="margin-top:18px">
                {{ lang._('Currently blocked') }}
                (<span id="selfcareTotal">0</span>)
                <button class="btn btn-default btn-xs" id="refreshSelfcareAct" style="margin-left:10px">
                    <span class="fa fa-refresh"></span> {{ lang._('Refresh') }}
                </button>
            </h4>
            <table id="selfcareTable">
                <thead>
                    <tr>
                        <th>{{ lang._('IP') }}</th>
                        <th>{{ lang._('Interface') }}</th>
                        <th>{{ lang._('Added') }}</th>
                        <th>{{ lang._('Expires') }}</th>
                        <th>{{ lang._('Categories') }}</th>
                        <th>{{ lang._('Action') }}</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>
    </div>
    <div id="permaban" class="tab-pane fade">
        {{ partial("layout_partials/base_form", ['fields': permabanForm, 'id': 'frm_permaban']) }}
        <div style="padding:10px 15px 15px 15px">
            <h4 style="margin-top:18px">
                {{ lang._('Add to Perma-Block') }}
            </h4>
            <div style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap">
                <div>
                    <label style="display:block;font-size:11px;color:#555">{{ lang._('IP address') }}</label>
                    <input type="text" id="permaban_new_ip" placeholder="1.2.3.4" class="form-control" style="width:160px"/>
                </div>
                <div>
                    <label style="display:block;font-size:11px;color:#555">{{ lang._('Note (optional)') }}</label>
                    <input type="text" id="permaban_new_note" placeholder="{{ lang._('e.g. seen brute-forcing SSH') }}" class="form-control" style="width:280px"/>
                </div>
                <div>
                    <button class="btn btn-primary btn-sm" id="permabanAddAct">
                        <span class="fa fa-plus"></span> {{ lang._('Add') }}
                    </button>
                </div>
            </div>
            <p style="color:#777;font-size:11px;margin-top:6px">
                {{ lang._('Perma-Block entries are stored in the local pf table only — no AbuseIPDB report is submitted on add. The decision to publicly flag an IP stays with you.') }}
            </p>
            <h4 style="margin-top:24px">
                {{ lang._('Currently blocked permanently') }}
                (<span id="permabanTotal">0</span>)
                <button class="btn btn-default btn-xs" id="refreshPermabanAct" style="margin-left:10px">
                    <span class="fa fa-refresh"></span> {{ lang._('Refresh') }}
                </button>
                <button class="btn btn-default btn-xs" id="permabanScanAct" style="margin-left:6px">
                    <span class="fa fa-bolt"></span> {{ lang._('Run auto-promote scan') }}
                </button>
            </h4>
            <table id="permabanTable">
                <thead>
                    <tr>
                        <th>{{ lang._('IP') }}</th>
                        <th>{{ lang._('Added') }}</th>
                        <th>{{ lang._('Source') }}</th>
                        <th>{{ lang._('Note') }}</th>
                        <th>{{ lang._('Action') }}</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>
    </div>
    <div id="logtab" class="tab-pane fade" style="padding:10px">
        <div style="margin-bottom:8px">
            <button class="btn btn-default btn-sm" id="refreshReportsAct">
                <span class="fa fa-refresh"></span> {{ lang._('Refresh') }}
            </button>
            <span id="reportsLastFetch" style="color:#666;font-size:11px;margin-left:10px"></span>
        </div>
        <h4 style="margin-top:0">{{ lang._('Recent reports') }}</h4>
        <table id="reportsTable">
            <thead>
                <tr>
                    <th>{{ lang._('Time') }}</th>
                    <th>{{ lang._('IP') }}</th>
                    <th>{{ lang._('Interface') }}</th>
                    <th>{{ lang._('Categories') }}</th>
                    <th>{{ lang._('Result') }}</th>
                    <th>{{ lang._('Message') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>
    </div>
    <div id="statstab" class="tab-pane fade" style="padding:10px">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:18px">
            <div>
                <h4 style="margin-top:0">{{ lang._('Self-defense — currently active per interface') }}</h4>
                <table id="stats_iface_sc_active" style="width:100%;font-size:12px"><tbody></tbody></table>
            </div>
            <div>
                <h4 style="margin-top:0">{{ lang._('Self-defense — total ever added per interface') }}</h4>
                <table id="stats_iface_sc_total" style="width:100%;font-size:12px"><tbody></tbody></table>
            </div>
            <div>
                <h4 style="margin-top:0">{{ lang._('Reports today per interface') }}</h4>
                <table id="stats_iface_rep_today" style="width:100%;font-size:12px"><tbody></tbody></table>
            </div>
            <div>
                <h4 style="margin-top:0">{{ lang._('Reports total per interface') }}</h4>
                <table id="stats_iface_rep_total" style="width:100%;font-size:12px"><tbody></tbody></table>
            </div>
        </div>
        <hr style="margin:20px 0">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:18px">
            <div>
                <h4 style="margin-top:0">{{ lang._('Reports — last 14 days') }}</h4>
                <table id="stats_daily_reports" style="width:100%;font-size:12px"><tbody></tbody></table>
            </div>
            <div>
                <h4 style="margin-top:0">{{ lang._('Self-defense additions — last 14 days') }}</h4>
                <table id="stats_daily_selfcare" style="width:100%;font-size:12px"><tbody></tbody></table>
            </div>
        </div>
    </div>
</div>

<section class="page-content-main">
    <div class="content-box" style="padding: 15px;">
        <button class="btn btn-primary" id="saveAct">
            <b>{{ lang._('Save') }}</b>
        </button>
        <button class="btn btn-default" id="testConnectionAct">
            {{ lang._('Test connection') }}
        </button>
        <button class="btn btn-default" id="downloadNowAct">
            {{ lang._('Download blacklist now') }}
        </button>
        <br/><br/>
        <div id="responseMsg" class="alert alert-info hidden" role="alert"></div>
    </div>
</section>
