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
    #reportsTable, #selfcareTable, #permabanTable, #whitelistTable { width: 100%; font-size: 12px; }
    #reportsTable td, #reportsTable th,
    #selfcareTable td, #selfcareTable th,
    #permabanTable td, #permabanTable th,
    #whitelistTable td, #whitelistTable th { padding: 4px 8px; border-bottom: 1px solid #eee; }
    #reportsTable th, #selfcareTable th, #permabanTable th, #whitelistTable th { background: #f4f4f4; text-align: left; }
</style>

<script>
    function fmtTs(ts) {
        if (!ts) return '—';
        var d = new Date(ts * 1000);
        return d.toLocaleString();
    }

    function fmtAgo(ts) {
        if (!ts) return '';
        var diff = Math.round(ts - Date.now()/1000);
        var sign = diff < 0 ? -1 : 1;
        var abs = Math.abs(diff);
        var unit, val;
        if (abs < 60)         { unit='s';  val=abs; }
        else if (abs < 3600)  { unit='m';  val=Math.round(abs/60); }
        else if (abs < 86400) { unit='h';  val=Math.round(abs/3600); }
        else                  { unit='d';  val=Math.round(abs/86400); }
        return sign < 0 ? (val + unit + ' ago') : ('in ' + val + unit);
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
                // v0.8: per-endpoint quota with last-seen freshness
                ['report','check','blacklist'].forEach(function(ep){
                    var q = (d.quota || {})[ep] || {};
                    var txt = (q.remaining === null || q.remaining === undefined)
                        ? '—'
                        : (q.remaining + (q.limit ? ' / ' + q.limit : ''));
                    $("#stat_q_" + ep).text(txt);
                    var age = q.last_seen ? fmtAgo(q.last_seen) : '';
                    var reset = q.reset_ts ? fmtAgo(q.reset_ts) + ' (reset)' : '';
                    $("#stat_q_" + ep + "_age").text(
                        [age && 'as of ' + age, reset].filter(Boolean).join(' · ')
                    );
                });
                // v0.8: snapshot history (only shown when at least one exists)
                var snaps = d.snapshots || [];
                if (snaps.length > 0) {
                    $("#stat_snapshots_wrap").show();
                    $("#stat_snapshots_count").text(snaps.length);
                    var $body = $("#stat_snapshots_body").empty();
                    snaps.forEach(function(s) {
                        var $tr = $('<tr>');
                        var $td1 = $('<td>').css('padding','2px 10px').append($('<tt>').text('#' + s.id));
                        var $td2 = $('<td>').css({'padding':'2px 10px','white-space':'nowrap'}).text(fmtTs(s.fetched_ts));
                        var $td3 = $('<td>').css({'padding':'2px 10px','text-align':'right'}).text((s.ip_count || 0).toLocaleString());
                        var $td4 = $('<td>').css({'padding':'2px 10px','text-align':'right','color':'#888'})
                            .text(s.quota_remaining === null || s.quota_remaining === undefined ? '—' : s.quota_remaining);
                        $tr.append($td1, $td2, $td3, $td4);
                        $body.append($tr);
                    });
                } else {
                    $("#stat_snapshots_wrap").hide();
                }
                $("#stat_reports_today").text(d.reports_today);
                $("#stat_reports_total").text(d.reports_total);
                $("#stat_selfcare_active").text((d.selfcare_active || 0).toLocaleString());
                $("#stat_selfcare_total").text((d.selfcare_total || 0).toLocaleString());
                $("#stat_permaban_count").text((d.permaban_count || 0).toLocaleString());
                $("#stat_whitelist_count").text((d.whitelist_count || 0).toLocaleString());
                renderStatsTab(d);
            }
        );
    }

    function renderIfaceTable(targetSel, dict, v6dict) {
        var $t = $(targetSel).empty();
        var keys = Object.keys(dict || {}).sort(function(a,b){ return (dict[b]||0) - (dict[a]||0); });
        if (keys.length === 0) {
            $t.append('<tr><td colspan="2" style="color:#888;padding:6px">—</td></tr>');
            return;
        }
        v6dict = v6dict || {};
        var max = Math.max.apply(null, keys.map(function(k){ return dict[k]; }));
        keys.forEach(function(k) {
            var total = dict[k] || 0;
            var v6    = v6dict[k] || 0;
            var v4    = Math.max(total - v6, 0);
            // Bar widths are relative to the largest interface count, so the
            // longest row hits ~100% and the rest scale below.
            var totalPct = max > 0 ? Math.round(total / max * 100) : 0;
            var v6Share  = total > 0 ? (v6 / total) : 0;
            var v6PctOfBar = Math.round(v6Share * 100);   // share inside the bar itself
            var v4PctOfBar = 100 - v6PctOfBar;
            var label = ifaceDescr[k] || k;
            var label4 = v4 > 0 ? v4.toLocaleString() : '';
            var label6 = v6 > 0 ? v6.toLocaleString() : '';
            var inner = '';
            // v4 segment (blue) — always render when v4 > 0
            if (v4 > 0) {
                inner += '<div title="IPv4: ' + v4 + '" style="background:#3498db;color:#fff;padding:2px 6px;'
                       + 'width:' + v4PctOfBar + '%;font-size:11px;text-align:left;'
                       + 'box-sizing:border-box;overflow:hidden">' + label4 + '</div>';
            }
            // v6 segment (purple) — always render when v6 > 0
            if (v6 > 0) {
                inner += '<div title="IPv6: ' + v6 + '" style="background:#8e44ad;color:#fff;padding:2px 6px;'
                       + 'width:' + Math.max(v6PctOfBar, 4) + '%;font-size:11px;text-align:left;'
                       + 'box-sizing:border-box;overflow:hidden">' + label6 + '</div>';
            }
            $t.append(
                '<tr>' +
                '<td style="white-space:nowrap;padding-right:8px"><b>' + label + '</b> <span style="color:#888;font-size:11px">' + k + '</span></td>' +
                '<td style="width:100%">' +
                '<div style="display:flex;width:' + Math.max(totalPct, 5) + '%;min-width:30px">' + inner + '</div>' +
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
            var total = p.count || 0;
            var v6    = p.count_v6 || 0;
            var v4    = Math.max(total - v6, 0);
            var totalPct = max > 0 ? Math.round(total / max * 100) : 0;
            var v6PctOfBar = total > 0 ? Math.round(v6 / total * 100) : 0;
            var v4PctOfBar = 100 - v6PctOfBar;
            var d = new Date(p.day);
            var dayLbl = d.toLocaleDateString(undefined, {weekday:'short', day:'2-digit', month:'2-digit'});
            var label4 = v4 > 0 ? v4.toLocaleString() : '';
            var label6 = v6 > 0 ? v6.toLocaleString() : '';
            var inner = '';
            if (v4 > 0) {
                inner += '<div title="IPv4: ' + v4 + '" style="background:#27ae60;color:#fff;padding:2px 6px;'
                       + 'width:' + v4PctOfBar + '%;font-size:11px;text-align:left;'
                       + 'box-sizing:border-box;overflow:hidden">' + label4 + '</div>';
            }
            if (v6 > 0) {
                inner += '<div title="IPv6: ' + v6 + '" style="background:#8e44ad;color:#fff;padding:2px 6px;'
                       + 'width:' + Math.max(v6PctOfBar, 4) + '%;font-size:11px;text-align:left;'
                       + 'box-sizing:border-box;overflow:hidden">' + label6 + '</div>';
            }
            if (!inner) {
                // total == 0 — render an empty thin sliver so the row stays visible
                inner = '<div style="background:#e0e0e0;width:100%;padding:2px 6px;font-size:11px;color:#888">0</div>';
            }
            $t.append(
                '<tr>' +
                '<td style="white-space:nowrap;padding-right:8px;font-size:11px">' + dayLbl + '</td>' +
                '<td style="width:100%">' +
                '<div style="display:flex;width:' + Math.max(totalPct, 1) + '%;min-width:30px">' + inner + '</div>' +
                '</td></tr>'
            );
        });
    }

    function renderStatsTab(d) {
        var v6 = d.by_iface_v6 || {};
        renderIfaceTable("#stats_iface_sc_active tbody", d.by_iface ? d.by_iface.selfcare_active : {}, v6.selfcare_active);
        renderIfaceTable("#stats_iface_sc_total tbody",  d.by_iface ? d.by_iface.selfcare_total  : {}, v6.selfcare_total);
        renderIfaceTable("#stats_iface_rep_today tbody", d.by_iface ? d.by_iface.reports_today   : {}, v6.reports_today);
        renderIfaceTable("#stats_iface_rep_total tbody", d.by_iface ? d.by_iface.reports_total   : {}, v6.reports_total);
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
        var limit = parseInt($("#selfcareLimit").val() || "300", 10);
        ajaxCall(
            url = "/api/abuseipdb/service/selfcare_list",
            sendData = {limit: limit},
            callback = function(resp) {
                if (!resp || resp.status !== 'ok') return;
                var rows = resp.data.rows;
                var total = resp.data.total_active;
                $("#selfcareTotal").text(total);
                $("#selfcareShown").text(rows.length);
                var tbody = $("#selfcareTable tbody").empty();
                if (rows.length === 0) {
                    tbody.append('<tr><td colspan="6" style="text-align:center;color:#888;padding:12px">{{ lang._("No active entries.") }}</td></tr>');
                } else {
                    rows.forEach(function(r) {
                        var $tr = $('<tr>');
                        $tr.append($('<td>').css('white-space', 'nowrap').append($('<tt>').text(r.ip)));
                        $tr.append($('<td>').text(fmtIface(r.iface)));
                        $tr.append($('<td>').text(fmtTs(r.added_ts)));
                        $tr.append($('<td>').text(fmtTs(r.expires_ts) + ' (' + fmtDuration(r.remaining_sec) + ')'));
                        $tr.append($('<td>').text(r.categories || ''));
                        // Action cell holds three buttons: remove (trash),
                        // whitelist (shield), permaban (bolt).
                        var $rm = $('<button class="btn btn-xs btn-default scRemoveBtn" title="{{ lang._('Remove from self-defense (false positive)') }}"><span class="fa fa-trash"></span></button>');
                        $rm.attr('data-ip', r.ip);
                        var $wl = $('<button class="btn btn-xs btn-info scWhitelistBtn" style="margin-left:4px" title="{{ lang._('Move to whitelist — no more blocks for this IP') }}"><span class="fa fa-shield"></span></button>');
                        $wl.attr('data-ip', r.ip);
                        var $btn = $('<button class="btn btn-xs btn-warning promoteBtn" style="margin-left:4px" title="{{ lang._('Promote to Perma-Block') }}"><span class="fa fa-bolt"></span></button>');
                        $btn.attr('data-ip', r.ip);
                        $tr.append($('<td>').css('white-space', 'nowrap').append($rm).append($wl).append($btn));
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
                    tbody.append('<tr><td colspan="7" style="text-align:center;color:#888;padding:12px">{{ lang._("No Perma-Block entries.") }}</td></tr>');
                } else {
                    rows.forEach(function(r) {
                        var $tr = $('<tr>');
                        $tr.append($('<td>').css('white-space', 'nowrap').append($('<tt>').text(r.ip)));
                        $tr.append($('<td>').text(fmtTs(r.added_ts)));
                        // Hits cell: bold total + tiny session-counter underneath
                        var hits = (r.hits || 0).toLocaleString();
                        var session = (r.current_session || 0).toLocaleString();
                        var $hitsTd = $('<td>').css('text-align', 'right').css('white-space', 'nowrap');
                        $hitsTd.append($('<b>').text(hits));
                        $hitsTd.append($('<div>').css({color: '#888', 'font-size': '11px'})
                                                  .text('seit Boot: ' + session));
                        $tr.append($hitsTd);
                        // Last-hit cell
                        $tr.append($('<td>').css('white-space', 'nowrap')
                                            .text(r.last_hit_ts ? fmtTs(r.last_hit_ts) : '—'));
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

    function refreshWhitelist() {
        ajaxCall(
            url = "/api/abuseipdb/service/whitelist_list",
            sendData = {limit: 500},
            callback = function(resp) {
                if (!resp || resp.status !== 'ok') return;
                var rows = resp.data.rows || [];
                $("#whitelistTotal").text(resp.data.total || 0);
                $("#whitelistSkips30d").text(resp.data.skips_30d_total || 0);
                var tbody = $("#whitelistTable tbody").empty();
                if (rows.length === 0) {
                    tbody.append('<tr><td colspan="5" style="text-align:center;color:#888;padding:12px">{{ lang._("No whitelist entries.") }}</td></tr>');
                    return;
                }
                rows.forEach(function(r) {
                    var $tr = $('<tr>');
                    $tr.append($('<td>').css('white-space','nowrap').append($('<tt>').text(r.ip)));
                    $tr.append($('<td>').text(fmtTs(r.added_ts)));
                    $tr.append($('<td>').text(r.source || ''));
                    $tr.append($('<td>').text(r.note || ''));
                    // Skip-counter doubles as a remove button cell.
                    var $td = $('<td>').css('white-space','nowrap');
                    var skip = (r.skips_30d || 0).toLocaleString();
                    $td.append($('<span>').css({color:'#888','font-size':'11px','margin-right':'8px'})
                                          .text(skip + ' {{ lang._("skips/30d") }}'));
                    var $rm = $('<button class="btn btn-xs btn-default whitelistRemoveBtn" title="{{ lang._('Remove from whitelist') }}"><span class="fa fa-trash"></span></button>');
                    $rm.attr('data-ip', r.ip);
                    $td.append($rm);
                    $tr.append($td);
                    tbody.append($tr);
                });
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
                        $tr.append($('<td>').css('white-space', 'nowrap').append($('<tt>').text(r.ip)));
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
            if (href === '#whitelist') refreshWhitelist();
            if (href === '#statstab') refreshStats();
        });
        $("#refreshReportsAct").click(refreshReports);
        $("#refreshSelfcareAct").click(refreshSelfcare);
        $("#selfcareLimit").change(refreshSelfcare);
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

        // v0.9.0: trash button on each row of the self-defense list — drops
        // a single false-positive entry without permabanning it.
        $("#selfcareTable").on("click", ".scRemoveBtn", function() {
            var ip = $(this).attr("data-ip");
            if (!ip) return;
            if (!confirm("{{ lang._('Remove ') }}" + ip + " {{ lang._('from self-defense list?') }}")) return;
            ajaxCall(
                url = "/api/abuseipdb/service/selfcare_remove",
                sendData = {ip: ip},
                callback = function(resp) {
                    refreshSelfcare();
                    refreshStats();
                }
            );
        });

        // v0.9.0: shield button — move IP to whitelist (lifts selfcare +
        // permaban, prevents future blocks/reports).
        $("#selfcareTable").on("click", ".scWhitelistBtn", function() {
            var ip = $(this).attr("data-ip");
            if (!ip) return;
            if (!confirm("{{ lang._('Whitelist ') }}" + ip + "?\n\n" +
                         "{{ lang._('This IP will no longer be blocked or reported. Any active self-defense or permaban entry will be lifted.') }}")) {
                return;
            }
            ajaxCall(
                url = "/api/abuseipdb/service/whitelist_add",
                sendData = {ip: ip, source: "selfcare", note: "false positive"},
                callback = function(resp) {
                    if (resp && resp.status === 'ok') {
                        refreshSelfcare();
                        refreshPermaban();
                        refreshStats();
                    } else {
                        alert((resp && resp.message) || "{{ lang._('Whitelist add failed') }}");
                    }
                }
            );
        });

        // v0.9.0: clear-all self-defense (false-positive recovery mode).
        $("#selfcareClearAllAct").click(function() {
            if (!confirm("{{ lang._('Clear the entire self-defense list?') }}\n\n" +
                         "{{ lang._('This unblocks every IP currently in the list. They may get re-added on the next reporter run. Use this only when several false positives slipped through.') }}")) {
                return;
            }
            ajaxCall(
                url = "/api/abuseipdb/service/selfcare_clear_all",
                sendData = {confirm: "yes"},
                callback = function(resp) {
                    var n = (resp && resp.removed) || 0;
                    $("#responseMsg").removeClass("hidden").html(
                        "{{ lang._('Cleared self-defense list:') }} " + n + " " + "{{ lang._('entries removed.') }}"
                    );
                    refreshSelfcare();
                    refreshStats();
                }
            );
        });

        // v0.9.0: Whitelist tab — add button.
        $("#whitelistAddAct").click(function() {
            var ip = ($("#whitelist_new_ip").val() || "").trim();
            var note = ($("#whitelist_new_note").val() || "").trim();
            if (!ip) { alert("{{ lang._('Enter an IP address.') }}"); return; }
            ajaxCall(
                url = "/api/abuseipdb/service/whitelist_add",
                sendData = {ip: ip, source: "manual", note: note},
                callback = function(resp) {
                    if (resp && resp.status === 'ok') {
                        $("#whitelist_new_ip").val("");
                        $("#whitelist_new_note").val("");
                        refreshWhitelist();
                        refreshStats();
                    } else {
                        alert((resp && resp.message) || "{{ lang._('Whitelist add failed') }}");
                    }
                }
            );
        });

        // v0.9.0: Whitelist tab — remove button per row.
        $("#whitelistTable").on("click", ".whitelistRemoveBtn", function() {
            var ip = $(this).attr("data-ip");
            if (!ip) return;
            if (!confirm("{{ lang._('Remove ') }}" + ip + " {{ lang._('from whitelist?') }}")) return;
            ajaxCall(
                url = "/api/abuseipdb/service/whitelist_remove",
                sendData = {ip: ip},
                callback = function(resp) {
                    refreshWhitelist();
                    refreshStats();
                }
            );
        });

        $("#refreshWhitelistAct").click(refreshWhitelist);

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
            <td class="lbl">{{ lang._('API quota') }}</td>
            <td>
                <table style="width:auto;font-size:11px;border-collapse:collapse">
                    <tr>
                        <td style="padding-right:10px;color:#555">/report</td>
                        <td><span id="stat_q_report">—</span></td>
                        <td style="padding-left:10px;color:#888" id="stat_q_report_age"></td>
                    </tr>
                    <tr>
                        <td style="padding-right:10px;color:#555">/check</td>
                        <td><span id="stat_q_check">—</span></td>
                        <td style="padding-left:10px;color:#888" id="stat_q_check_age"></td>
                    </tr>
                    <tr>
                        <td style="padding-right:10px;color:#555">/blacklist</td>
                        <td><span id="stat_q_blacklist">—</span></td>
                        <td style="padding-left:10px;color:#888" id="stat_q_blacklist_age"></td>
                    </tr>
                </table>
            </td>
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
        <tr>
            <td class="lbl">{{ lang._('Whitelist entries') }}</td>
            <td><span id="stat_whitelist_count">—</span></td>
        </tr>
    </table>
    <div id="stat_snapshots_wrap" style="margin-top:10px; display:none">
        <details>
            <summary style="cursor:pointer; font-size:12px; color:#555">
                {{ lang._('Blacklist snapshot history') }}
                (<span id="stat_snapshots_count">0</span>)
            </summary>
            <table style="width:auto; font-size:11px; margin-top:6px; border-collapse:collapse">
                <thead>
                    <tr style="background:#e7eef4">
                        <th style="padding:3px 10px; text-align:left">ID</th>
                        <th style="padding:3px 10px; text-align:left">{{ lang._('Fetched') }}</th>
                        <th style="padding:3px 10px; text-align:right">{{ lang._('IPs') }}</th>
                        <th style="padding:3px 10px; text-align:right">{{ lang._('Quota at fetch') }}</th>
                    </tr>
                </thead>
                <tbody id="stat_snapshots_body"></tbody>
            </table>
        </details>
    </div>
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
    <li><a data-toggle="tab" href="#whitelist">{{ lang._('Whitelist') }}</a></li>
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
                (<span id="selfcareShown">0</span> {{ lang._('of') }} <span id="selfcareTotal">0</span>)
                <label style="margin-left:14px;font-weight:normal;font-size:12px">
                    {{ lang._('Show:') }}
                    <select id="selfcareLimit" class="selectpicker" style="font-size:12px">
                        <option value="50">50</option>
                        <option value="100">100</option>
                        <option value="200">200</option>
                        <option value="300" selected>300</option>
                        <option value="500">500</option>
                    </select>
                </label>
                <button class="btn btn-default btn-xs" id="refreshSelfcareAct" style="margin-left:10px">
                    <span class="fa fa-refresh"></span> {{ lang._('Refresh') }}
                </button>
                <button class="btn btn-danger btn-xs" id="selfcareClearAllAct" style="margin-left:6px"
                        title="{{ lang._('Clear every active self-defense entry — false-positive recovery') }}">
                    <span class="fa fa-eraser"></span> {{ lang._('Clear all') }}
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
                        <th style="text-align:right">{{ lang._('Hits') }}</th>
                        <th>{{ lang._('Last hit') }}</th>
                        <th>{{ lang._('Source') }}</th>
                        <th>{{ lang._('Note') }}</th>
                        <th>{{ lang._('Action') }}</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>
    </div>
    <div id="whitelist" class="tab-pane fade">
        <div style="padding:10px 15px 15px 15px">
            <p style="color:#555;font-size:12px;margin:0 0 8px 0">
                {{ lang._('Whitelisted IPs are never reported, blocked, permabanned, or included in the downloaded blacklist. Use this for known-good sources (your monitoring, remote-support tools, etc.) that occasionally trip the reporter.') }}
            </p>
            <h4 style="margin-top:18px">
                {{ lang._('Add to Whitelist') }}
            </h4>
            <div style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap">
                <div>
                    <label style="display:block;font-size:11px;color:#555">{{ lang._('IP address') }}</label>
                    <input type="text" id="whitelist_new_ip" placeholder="1.2.3.4" class="form-control" style="width:160px"/>
                </div>
                <div>
                    <label style="display:block;font-size:11px;color:#555">{{ lang._('Note (optional)') }}</label>
                    <input type="text" id="whitelist_new_note" placeholder="{{ lang._('e.g. PCVisit remote support') }}" class="form-control" style="width:280px"/>
                </div>
                <div>
                    <button class="btn btn-primary btn-sm" id="whitelistAddAct">
                        <span class="fa fa-plus"></span> {{ lang._('Add') }}
                    </button>
                </div>
            </div>
            <p style="color:#777;font-size:11px;margin-top:6px">
                {{ lang._('Adding an IP that is currently blocked (self-defense or perma-block) will lift those entries automatically.') }}
            </p>
            <h4 style="margin-top:24px">
                {{ lang._('Whitelisted IPs') }}
                (<span id="whitelistTotal">0</span>,
                <span id="whitelistSkips30d">0</span> {{ lang._('skips in last 30d') }})
                <button class="btn btn-default btn-xs" id="refreshWhitelistAct" style="margin-left:10px">
                    <span class="fa fa-refresh"></span> {{ lang._('Refresh') }}
                </button>
            </h4>
            <table id="whitelistTable">
                <thead>
                    <tr>
                        <th>{{ lang._('IP') }}</th>
                        <th>{{ lang._('Added') }}</th>
                        <th>{{ lang._('Source') }}</th>
                        <th>{{ lang._('Note') }}</th>
                        <th>{{ lang._('Skips / Action') }}</th>
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
