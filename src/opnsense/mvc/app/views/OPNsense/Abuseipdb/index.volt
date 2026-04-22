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
    #reportsTable { width: 100%; font-size: 12px; }
    #reportsTable td, #reportsTable th { padding: 4px 8px; border-bottom: 1px solid #eee; }
    #reportsTable th { background: #f4f4f4; text-align: left; }
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
                    return;
                }
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
        );
    }

    $(document).ready(function() {
        var data_get_map = {'frm_general': "/api/abuseipdb/settings/get",
                            'frm_blacklist': "/api/abuseipdb/settings/get",
                            'frm_reporter': "/api/abuseipdb/settings/get"};

        mapDataToFormUI(data_get_map).done(function(){
            updateServiceControlUI('abuseipdb');
        });

        function saveAll() {
            saveFormToEndpoint(
                url = "/api/abuseipdb/settings/set",
                formid = 'frm_general',
                callback_ok = function(){
                    saveFormToEndpoint(
                        url = "/api/abuseipdb/settings/set",
                        formid = 'frm_blacklist',
                        callback_ok = function(){
                            saveFormToEndpoint(
                                url = "/api/abuseipdb/settings/set",
                                formid = 'frm_reporter',
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
            if ($(e.target).attr('href') === '#logtab') refreshReports();
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
    </table>
</div>

<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#general">{{ lang._('General') }}</a></li>
    <li><a data-toggle="tab" href="#blacklist">{{ lang._('Blacklist') }}</a></li>
    <li><a data-toggle="tab" href="#reporter">{{ lang._('Reporter') }}</a></li>
    <li><a data-toggle="tab" href="#logtab">{{ lang._('Log') }}</a></li>
</ul>

<div class="tab-content content-box">
    <div id="general" class="tab-pane fade in active">
        {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general']) }}
    </div>
    <div id="blacklist" class="tab-pane fade">
        {{ partial("layout_partials/base_form", ['fields': blacklistForm, 'id': 'frm_blacklist']) }}
    </div>
    <div id="reporter" class="tab-pane fade">
        {{ partial("layout_partials/base_form", ['fields': reporterForm, 'id': 'frm_reporter']) }}
    </div>
    <div id="logtab" class="tab-pane fade" style="padding:10px">
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
