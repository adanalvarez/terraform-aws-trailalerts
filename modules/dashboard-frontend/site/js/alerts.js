/**
 * alerts.js — Alert history with server-side time/severity filter,
 *             client-side sort and text search.
 *
 * Globals defined here:
 *   loadAlerts(), sortAlerts(), renderAlertsTable(), loadMoreAlerts(),
 *   viewAlertDetail(), closeModal()
 *
 * Depends on: api() (api.js), toast() / esc() / escAttr() / formatTime() (ui.js)
 */
'use strict';

var alertsNextToken  = null;
var alertsCache      = [];
var alertsSortField  = 'timestamp';
var alertsSortDir    = 'desc';
var severityOrder    = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// -------------------------------------------------------
// Load
// -------------------------------------------------------

async function loadAlerts(append) {
    var ruleSearch = document.getElementById('alert-rule-filter').value;
    var severity   = document.getElementById('alert-severity-filter').value;
    var hours      = document.getElementById('alert-hours-filter').value;

    if (!append) { alertsNextToken = null; alertsCache = []; }

    var tbody = document.getElementById('alerts-body');
    if (!append) tbody.innerHTML = '<tr><td colspan="7" class="loading"><div class="spinner"></div></td></tr>';

    try {
        var url = '/api/alerts?hours=' + hours + '&limit=50';
        if (ruleSearch) url += '&rule=' + encodeURIComponent(ruleSearch);
        if (severity) url += '&severity=' + encodeURIComponent(severity);
        if (alertsNextToken) url += '&nextToken=' + encodeURIComponent(alertsNextToken);

        var data = await api(url);

        alertsCache     = append ? alertsCache.concat(data.alerts) : data.alerts;
        alertsNextToken = data.nextToken || null;

        var loadMoreBtn = document.getElementById('alerts-load-more');
        loadMoreBtn.style.display = (alertsNextToken && data.alerts.length > 0) ? '' : 'none';

        renderAlertsTable();
    } catch (e) {
        if (!append) tbody.innerHTML = '<tr><td colspan="7" style="color:var(--critical);">Failed to load alerts: ' + esc(e.message) + '</td></tr>';
        else toast('Failed to load more alerts: ' + e.message, 'error');
    }
}

// -------------------------------------------------------
// Sort & Render
// -------------------------------------------------------

function sortAlerts(thEl, field) {
    if (alertsSortField === field) {
        alertsSortDir = alertsSortDir === 'asc' ? 'desc' : 'asc';
    } else {
        alertsSortField = field;
        alertsSortDir = field === 'timestamp' ? 'desc' : 'asc';
    }
    thEl.closest('thead').querySelectorAll('th.sortable').forEach(function (h) { h.classList.remove('asc', 'desc'); });
    thEl.classList.add(alertsSortDir);
    renderAlertsTable();
}

function renderAlertsTable() {
    var tbody      = document.getElementById('alerts-body');
    var ruleSearch = (document.getElementById('alert-rule-filter').value || '').toLowerCase();

    var filtered = alertsCache;
    if (ruleSearch) {
        filtered = alertsCache.filter(function (a) {
            return (a.sigmaRuleTitle || '').toLowerCase().includes(ruleSearch) ||
                   (a.eventName || '').toLowerCase().includes(ruleSearch) ||
                   (a.actor || '').toLowerCase().includes(ruleSearch) ||
                   (a.sourceIp || '').toLowerCase().includes(ruleSearch);
        });
    }

    filtered.sort(function (a, b) {
        var va = a[alertsSortField] || '';
        var vb = b[alertsSortField] || '';
        if (alertsSortField === 'timestamp') {
            va = new Date(va).getTime() || 0;
            vb = new Date(vb).getTime() || 0;
            return alertsSortDir === 'asc' ? va - vb : vb - va;
        }
        if (alertsSortField === 'severity') {
            va = severityOrder[va] !== undefined ? severityOrder[va] : 5;
            vb = severityOrder[vb] !== undefined ? severityOrder[vb] : 5;
            return alertsSortDir === 'asc' ? va - vb : vb - va;
        }
        var cmp = String(va).localeCompare(String(vb));
        return alertsSortDir === 'asc' ? cmp : -cmp;
    });

    tbody.innerHTML = '';
    if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--text-muted); padding:2rem;">No alerts found for the selected filters</td></tr>';
        document.getElementById('alerts-count').textContent = alertsCache.length > 0
            ? '0 alerts matching search (from ' + alertsCache.length + ' loaded)'
            : 'No alerts';
        return;
    }

    filtered.forEach(function (a) {
        var tr = document.createElement('tr');
        tr.innerHTML =
            '<td style="white-space:nowrap;">' + esc(formatTime(a.timestamp)) + '</td>' +
            '<td title="' + escAttr(a.sigmaRuleTitle || '') + '" style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">' + esc(a.sigmaRuleTitle || '') + '</td>' +
            '<td><span class="badge badge-' + (a.severity || 'info') + '">' + esc(a.severity || '?') + '</span></td>' +
            '<td title="' + escAttr(a.eventName || '') + '" style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">' + esc(a.eventName || '') + '</td>' +
            '<td title="' + escAttr(a.actor || '') + '" style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">' + esc(a.actor || '') + '</td>' +
            '<td>' + esc(a.sourceIp || '') + '</td>' +
            '<td><button class="btn btn-secondary btn-sm" onclick="viewAlertDetail(\'' + escAttr(a.pk) + '\',\'' + escAttr(a.sk) + '\')">Detail</button></td>';
        tbody.appendChild(tr);
    });

    var countEl = document.getElementById('alerts-count');
    countEl.textContent = filtered.length + ' alert' + (filtered.length !== 1 ? 's' : '') +
        (filtered.length < alertsCache.length ? ' (filtered from ' + alertsCache.length + ')' : '');
}

function loadMoreAlerts() {
    loadAlerts(true);
}

// -------------------------------------------------------
// Alert Detail Modal
// -------------------------------------------------------

async function viewAlertDetail(pk, sk) {
    var modal   = document.getElementById('alert-modal');
    var content = document.getElementById('alert-detail-content');
    content.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
    modal.classList.add('active');

    try {
        var data = await api('/api/alerts/detail?pk=' + encodeURIComponent(pk) + '&sk=' + encodeURIComponent(sk));
        var a = data.alert;
        var rawEvent = '';
        try { rawEvent = JSON.stringify(JSON.parse(a.rawEvent || '{}'), null, 2); } catch (_) { rawEvent = a.rawEvent || ''; }

        content.innerHTML =
            '<div style="display:grid; grid-template-columns:1fr 1fr; gap:0.75rem; margin-bottom:1rem;">' +
            '<div><strong>Rule:</strong> ' + esc(a.sigmaRuleTitle || '') + '</div>' +
            '<div><strong>Severity:</strong> <span class="badge badge-' + (a.severity || 'info') + '">' + esc(a.severity || '') + '</span></div>' +
            '<div><strong>Event:</strong> ' + esc(a.eventName || '') + '</div>' +
            '<div><strong>Time:</strong> ' + esc(a.timestamp || '') + '</div>' +
            '<div><strong>Actor:</strong> ' + esc(a.actor || '') + '</div>' +
            '<div><strong>Source IP:</strong> ' + esc(a.sourceIp || '') + '</div>' +
            '<div><strong>Account:</strong> ' + esc(a.accountId || '') + '</div>' +
            '<div><strong>User Agent:</strong> ' + esc(a.userAgent || '') + '</div>' +
            '</div>' +
            '<h4 style="margin-bottom:0.5rem;">Raw CloudTrail Event</h4>' +
            '<pre>' + esc(rawEvent) + '</pre>';
    } catch (e) {
        content.innerHTML = '<p style="color:var(--critical);">Failed to load detail: ' + esc(e.message) + '</p>';
    }
}

function closeModal() {
    document.getElementById('alert-modal').classList.remove('active');
}

// Close modal on overlay click or Escape key
document.getElementById('alert-modal').addEventListener('click', function (e) {
    if (e.target === this) closeModal();
});
document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && document.getElementById('alert-modal').classList.contains('active')) {
        closeModal();
    }
});
