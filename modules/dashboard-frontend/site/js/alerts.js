/**
 * alerts.js - Alert history with evidence-first table and detail view.
 */
'use strict';

var alertsNextToken = null;
var alertsCache = [];
var alertsSortField = 'timestamp';
var alertsSortDir = 'desc';
var severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
var alertSeverityKeys = ['critical', 'high', 'medium', 'low', 'info'];

function syncAlertSeverityTabs() {
    var current = document.getElementById('alert-severity-filter').value || '';
    document.querySelectorAll('#alert-severity-tabs .filter-tab').forEach(function (tab) {
        var isActive = (tab.dataset.severity || '') === current;
        tab.classList.toggle('active', isActive);
        tab.setAttribute('aria-pressed', isActive ? 'true' : 'false');
    });
}

function setAlertSeverityFilter(severity) {
    document.getElementById('alert-severity-filter').value = severity || '';
    syncAlertSeverityTabs();
    loadAlerts();
}

function setAlertCountChip(key, value) {
    var el = document.querySelector('[data-count-for="' + key + '"]');
    if (el) el.textContent = value === null || value === undefined ? '-' : String(value);
}

async function updateAlertSeverityCounts(hours) {
    alertSeverityKeys.concat(['all']).forEach(function (key) { setAlertCountChip(key, '-'); });
    try {
        var stats = await api('/api/alerts/stats?hours=' + encodeURIComponent(hours));
        var bySeverity = stats.bySeverity || {};
        setAlertCountChip('all', stats.totalAlerts || 0);
        alertSeverityKeys.forEach(function (key) { setAlertCountChip(key, bySeverity[key] || 0); });
    } catch (_) {
        alertSeverityKeys.concat(['all']).forEach(function (key) { setAlertCountChip(key, '-'); });
    }
}

async function loadAlerts(append) {
    var ruleSearch = document.getElementById('alert-rule-filter').value;
    var severity = document.getElementById('alert-severity-filter').value;
    var source = document.getElementById('alert-source-filter').value;
    var hours = document.getElementById('alert-hours-filter').value;

    if (!append) {
        alertsNextToken = null;
        alertsCache = [];
        syncAlertSeverityTabs();
        updateAlertSeverityCounts(hours);
    }

    var tbody = document.getElementById('alerts-body');
    if (!append) tbody.innerHTML = '<tr><td colspan="7" class="loading"><div class="spinner"></div></td></tr>';

    try {
        var url = '/api/alerts?hours=' + encodeURIComponent(hours) + '&limit=50';
        if (ruleSearch) url += '&rule=' + encodeURIComponent(ruleSearch);
        if (severity) url += '&severity=' + encodeURIComponent(severity);
        if (source) url += '&source=' + encodeURIComponent(source);
        if (alertsNextToken) url += '&nextToken=' + encodeURIComponent(alertsNextToken);

        var data = await api(url);
        var loadedAlerts = data.alerts || [];
        alertsCache = append ? alertsCache.concat(loadedAlerts) : loadedAlerts;
        alertsNextToken = data.nextToken || null;

        setHidden('alerts-load-more', !(alertsNextToken && loadedAlerts.length > 0));
        renderAlertsTable();
    } catch (e) {
        if (!append) tbody.innerHTML = emptyTableRow(7, 'Failed to load alerts', e.message);
        else toast('Failed to load more alerts: ' + e.message, 'error');
    }
}

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
    var tbody = document.getElementById('alerts-body');
    var ruleSearch = (document.getElementById('alert-rule-filter').value || '').toLowerCase();

    var filtered = alertsCache;
    if (ruleSearch) {
        filtered = alertsCache.filter(function (alert) {
            return (alert.sigmaRuleTitle || '').toLowerCase().includes(ruleSearch) ||
                (alert.eventName || '').toLowerCase().includes(ruleSearch) ||
                (alert.actor || '').toLowerCase().includes(ruleSearch) ||
                (alert.sourceIp || '').toLowerCase().includes(ruleSearch) ||
                (alert.sourceType || '').toLowerCase().includes(ruleSearch) ||
                (alert.accountId || '').toLowerCase().includes(ruleSearch) ||
                (alert.target || '').toLowerCase().includes(ruleSearch);
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
            va = severityOrder[String(va).toLowerCase()] !== undefined ? severityOrder[String(va).toLowerCase()] : 5;
            vb = severityOrder[String(vb).toLowerCase()] !== undefined ? severityOrder[String(vb).toLowerCase()] : 5;
            return alertsSortDir === 'asc' ? va - vb : vb - va;
        }
        var cmp = String(va).localeCompare(String(vb));
        return alertsSortDir === 'asc' ? cmp : -cmp;
    });

    if (filtered.length === 0) {
        tbody.innerHTML = emptyTableRow(7, 'No alerts found', 'Try a wider time window, another severity, or a different search term.');
        document.getElementById('alerts-count').textContent = alertsCache.length > 0
            ? '0 alerts matching search from ' + alertsCache.length + ' loaded'
            : 'No alerts loaded';
        return;
    }

    tbody.innerHTML = filtered.map(function (alert) {
        var severityCell = severityBadge(alert.severity);
        if (alert.correlatedWith) {
            severityCell += ' <span class="badge badge-correlated" title="Correlated with: ' + escAttr(alert.correlatedWith) + '">Correlated</span>';
        }
        return '<tr>' +
            '<td class="cell-nowrap"><div class="mono">' + esc(formatTime(alert.timestamp)) + '</div></td>' +
            '<td class="alert-row-title" title="' + escAttr(alert.sigmaRuleTitle || '') + '"><div class="cell-primary">' + esc(alert.sigmaRuleTitle || 'Unknown rule') + '</div><div class="cell-secondary mono">' + esc(alert.sigmaRuleId || '') + '</div></td>' +
            '<td class="cell-nowrap">' + severityCell + '</td>' +
            '<td title="' + escAttr(alert.eventName || '') + '"><div class="cell-primary">' + esc(alert.eventName || '') + '</div><div class="cell-secondary">' + esc(formatAlertSource(alert.sourceType || alert.eventType || '')) + '</div></td>' +
            '<td title="' + escAttr(alert.actor || '') + '"><div class="mono">' + esc(alert.actor || '') + '</div></td>' +
            '<td title="' + escAttr(alert.sourceIp || '') + '"><div class="mono">' + esc(alert.sourceIp || '') + '</div><div class="cell-secondary mono">' + esc(alert.accountId || '') + '</div></td>' +
            '<td class="cell-nowrap"><button class="btn btn-secondary btn-sm" data-action="view-alert" data-pk="' + escAttr(alert.pk) + '" data-sk="' + escAttr(alert.sk) + '">Detail</button></td>' +
            '</tr>';
    }).join('');

    var countEl = document.getElementById('alerts-count');
    countEl.textContent = filtered.length + ' alert' + (filtered.length !== 1 ? 's' : '') +
        (filtered.length < alertsCache.length ? ' filtered from ' + alertsCache.length : ' loaded');
}

function formatAlertSource(source) {
    var value = String(source || '').toLowerCase();
    if (value === 'guardduty') return 'GuardDuty';
    if (value === 'cloudtrail') return 'CloudTrail';
    return source || '';
}

function loadMoreAlerts() {
    loadAlerts(true);
}

function valueOrDash(value) {
    if (value === null || value === undefined || value === '') return '-';
    return value;
}

function evidenceRow(label, value, mono) {
    var classes = mono ? 'evidence-value mono' : 'evidence-value';
    return '<div class="evidence-row"><div class="evidence-label">' + esc(label) + '</div><div class="' + classes + '">' + esc(valueOrDash(value)) + '</div></div>';
}

function evidenceSection(title, rows) {
    return '<section class="evidence-card"><h4>' + esc(title) + '</h4><div class="evidence-list">' + rows.join('') + '</div></section>';
}

function parseRawEvent(rawEvent) {
    if (!rawEvent) return '';
    try {
        return JSON.stringify(JSON.parse(rawEvent), null, 2);
    } catch (_) {
        return String(rawEvent);
    }
}

async function viewAlertDetail(pk, sk) {
    var modal = document.getElementById('alert-modal');
    var content = document.getElementById('alert-detail-content');
    content.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
    modal.classList.add('active');

    try {
        var data = await api('/api/alerts/detail?pk=' + encodeURIComponent(pk) + '&sk=' + encodeURIComponent(sk));
        var alert = data.alert || {};
        var rawEvent = parseRawEvent(alert.rawEvent);
        var correlated = alert.correlatedWith ? '<span class="badge badge-correlated">Correlated</span>' : '';
        var badging = '<div class="badge-group">' + severityBadge(alert.severity) + correlated + '</div>';

        var contextRows = [
            evidenceRow('Time', alert.timestamp, true),
            evidenceRow('Event', alert.eventName, false),
            evidenceRow('Source type', alert.sourceType, false),
            evidenceRow('Event type', alert.eventType, false),
        ];
        var actorRows = [
            evidenceRow('Actor', alert.actor, true),
            evidenceRow('Source IP', alert.sourceIp, true),
            evidenceRow('User agent', alert.userAgent, true),
        ];
        var awsRows = [
            evidenceRow('Account', alert.accountId, true),
            evidenceRow('Region', alert.awsRegion || alert.region, true),
            evidenceRow('Target', alert.target, true),
            evidenceRow('Rule ID', alert.sigmaRuleId, true),
        ];
        var relationshipRows = [
            evidenceRow('Correlated with', alert.correlatedWith, false),
            evidenceRow('Dashboard key', alert.sk, true),
        ];

        content.innerHTML =
            '<div class="alert-detail-hero">' +
            '<div><div class="alert-detail-title">' + esc(alert.sigmaRuleTitle || 'Unknown rule') + '</div>' +
            '<div class="alert-detail-subtitle">Security event evidence for this detection.</div></div>' + badging + '</div>' +
            '<div class="evidence-grid">' +
            evidenceSection('Event evidence', contextRows) +
            evidenceSection('Actor and source', actorRows) +
            evidenceSection('AWS context', awsRows) +
            evidenceSection('Relationship', relationshipRows) +
            '</div>' +
            '<details class="raw-details"><summary>Raw alert event</summary><pre>' + esc(rawEvent || 'No raw event stored for this alert.') + '</pre></details>';
    } catch (e) {
        content.innerHTML = '<div class="notice">Failed to load alert detail: ' + esc(e.message) + '</div>';
    }
}

function closeModal() {
    document.getElementById('alert-modal').classList.remove('active');
}

document.getElementById('alert-modal').addEventListener('click', function (event) {
    if (event.target === this) closeModal();
});

document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape' && document.getElementById('alert-modal').classList.contains('active')) {
        closeModal();
    }
});
