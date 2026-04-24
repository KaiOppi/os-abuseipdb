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
    #reportsTable, #selfcareTable { width: 100%; font-size: 12px; }
    #reportsTable td, #reportsTable th,
    #selfcareTable td, #selfcareTable th { padding: 4px 8px; border-bottom: 1px solid #eee; }
    #reportsTable th, #selfcareTable th { background: #f4f4f4; text-align: left; }
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
                $("#stat_bl_count").text(d.blocklist_ips.toLocaleString());
                $("#stat_bl_last").text(fmtTs(d.blocklist_last_update));
                $("#stat_last_run").text(fmtTs(d.last_run));
                $("#stat_last_ok").text(d.last_run_ok === null ? '—' : (d.last_run_ok ? 'OK' : 'failed'))
                                   .toggleClass('ok', d.last_run_ok === true)
                                   .toggleClass('warn', d.last_run_ok === false);
                $("#stat_quota").text(d.quota_remaining === null ? '—' : d.quota_remaining);
                $("#stat_reports_today").text(d.reports_today);
                $("#stat_reports_total").text(d.reports_total);
            }
        );
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
                    tbody.append('<tr><td colspan="4" style="text-align:center;color:#888;padding:12px">{{ lang._("No active entries.") }}</td></tr>');
                } else {
                    rows.forEach(function(r) {
                        tbody.append(
                            '<tr>' +
                            '<td><tt>' + r.ip + '</tt></td>' +
                            '<td>' + fmtTs(r.added_ts) + '</td>' +
                            '<td>' + fmtTs(r.expires_ts) + ' (' + fmtDuration(r.remaining_sec) + ')</td>' +
                            '<td>' + (r.categories || '') + '</td>' +
                            '</tr>'
                        );
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
                    tbody.append('<tr><td colspan="5" style="text-align:center;color:#888;padding:12px">{{ lang._("No reports yet.") }}</td></tr>');
                } else {
                    rows.forEach(function(r) {
                        var cls = r.ok ? 'ok' : 'warn';
                        tbody.append(
                            '<tr>' +
                            '<td>' + fmtTs(r.ts) + '</td>' +
                            '<td><tt>' + r.ip + '</tt></td>' +
                            '<td>' + r.categories + '</td>' +
                            '<td class="' + cls + '">' + (r.ok ? 'OK' : 'failed') + '</td>' +
                            '<td>' + $('<div>').text(r.message).html() + '</td>' +
                            '</tr>'
                        );
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
                            'frm_selfcare': "/api/abuseipdb/settings/get"};

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
            if ($(e.target).attr('href') === '#logtab') {
                refreshReports();
                refreshSelfcare();
            }
        });
        $("#refreshReportsAct").click(function(){ refreshReports(); refreshSelfcare(); });

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
    <li><a data-toggle="tab" href="#logtab">{{ lang._('Log') }}</a></li>
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
                    <th>{{ lang._('Categories') }}</th>
                    <th>{{ lang._('Result') }}</th>
                    <th>{{ lang._('Message') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>

        <h4 style="margin-top:18px">
            {{ lang._('Self-Defense active blocks') }}
            (<span id="selfcareTotal">0</span>)
        </h4>
        <table id="selfcareTable">
            <thead>
                <tr>
                    <th>{{ lang._('IP') }}</th>
                    <th>{{ lang._('Added') }}</th>
                    <th>{{ lang._('Expires') }}</th>
                    <th>{{ lang._('Categories') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>
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
