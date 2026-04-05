/**
 * overview.js — Dashboard overview page (stats + top rules).
 *
 * Globals defined here: loadOverview()
 *
 * Depends on: api() (api.js), esc() (ui.js), toast() (ui.js)
 */
'use strict';

async function loadOverview() {
    try {
        var results = await Promise.all([
            api('/api/alerts/stats?hours=24').catch(function () { return { totalAlerts: 0, bySeverity: {}, topRules: [] }; }),
            api('/api/rules').catch(function () { return { count: 0 }; }),
        ]);
        var stats     = results[0];
        var rulesData = results[1];

        document.getElementById('stat-total').textContent    = stats.totalAlerts || 0;
        document.getElementById('stat-critical').textContent = (stats.bySeverity || {}).critical || 0;
        document.getElementById('stat-high').textContent     = (stats.bySeverity || {}).high || 0;
        document.getElementById('stat-medium').textContent   = (stats.bySeverity || {}).medium || 0;
        document.getElementById('stat-rules').textContent    = rulesData.count || 0;

        var tbody = document.getElementById('top-rules-body');
        tbody.innerHTML = '';
        (stats.topRules || []).forEach(function (r) {
            tbody.innerHTML += '<tr><td>' + esc(r.rule) + '</td><td>' + esc(r.count) + '</td></tr>';
        });
        if (!stats.topRules || stats.topRules.length === 0) {
            tbody.innerHTML = '<tr><td colspan="2" style="text-align:center; color:var(--text-muted);">No alerts in the last 24 hours</td></tr>';
        }
    } catch (e) {
        toast('Failed to load overview: ' + e.message, 'error');
    }
}
