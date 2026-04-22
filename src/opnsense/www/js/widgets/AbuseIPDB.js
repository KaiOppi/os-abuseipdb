/*
 * Copyright (c) 2026 Kai Schlestein
 * BSD 2-Clause.
 */

export default class AbuseIPDB extends BaseWidget {
    constructor(config) {
        super(config);
        this.tickTimeout = 30;
    }

    getMarkup() {
        let $wrap = $('<div class="os-abuseipdb-widget" style="font-size:12px;"></div>');
        $wrap.html(`
            <table style="width:100%">
                <tr><td style="color:#555">${this.translations.blocklist}</td>
                    <td style="text-align:right"><b><span id="ab-count">—</span></b></td></tr>
                <tr><td style="color:#555">${this.translations.last_download}</td>
                    <td style="text-align:right"><span id="ab-last">—</span></td></tr>
                <tr><td style="color:#555">${this.translations.quota}</td>
                    <td style="text-align:right"><span id="ab-quota">—</span></td></tr>
                <tr><td style="color:#555">${this.translations.reports_today}</td>
                    <td style="text-align:right"><span id="ab-today">—</span></td></tr>
                <tr><td style="color:#555">${this.translations.reports_total}</td>
                    <td style="text-align:right"><span id="ab-total">—</span></td></tr>
            </table>
            <div style="margin-top:6px;text-align:right">
                <a href="/ui/abuseipdb/" style="font-size:11px">${this.translations.settings} &rarr;</a>
            </div>
        `);
        return $wrap;
    }

    _fmtTs(ts) {
        if (!ts) return '—';
        let d = new Date(ts * 1000);
        return d.toLocaleString();
    }

    async onMarkupRendered() {
        return this.onWidgetTick();
    }

    async onWidgetTick() {
        try {
            const resp = await $.ajax({url: '/api/abuseipdb/service/stats', type: 'GET', dataType: 'json', timeout: 5000});
            if (!resp || resp.status !== 'ok') return;
            const d = resp.data;
            $('#ab-count', this.$widget).text((d.blocklist_ips || 0).toLocaleString());
            $('#ab-last', this.$widget).text(this._fmtTs(d.blocklist_last_update));
            $('#ab-quota', this.$widget).text(d.quota_remaining === null ? '—' : d.quota_remaining);
            $('#ab-today', this.$widget).text(d.reports_today || 0);
            $('#ab-total', this.$widget).text(d.reports_total || 0);
        } catch (e) {
            // silent — plugin may be disabled
        }
    }
}
