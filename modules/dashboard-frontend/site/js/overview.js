/**
 * overview.js - Compact dashboard overview with attention-focused stats.
 */
'use strict';

async function overviewFetch(path) {
    try {
        return { ok: true, data: await api(path) };
    } catch (error) {
        return { ok: false, error: error };
    }
}

function setOverviewStat(id, value, degraded) {
    var el = document.getElementById(id);
    if (el) el.textContent = degraded ? '-' : String(value || 0);
}

function setOverviewDelta(id, currentValue, compareValue, label, degraded) {
    var el = document.getElementById(id);
    if (!el) return;
    el.classList.remove('delta-up', 'delta-down', 'delta-flat');
    if (degraded) {
        el.textContent = label + ' -';
        el.classList.add('delta-flat');
        return;
    }

    var delta = Number(currentValue || 0) - Number(compareValue || 0);
    var sign = delta > 0 ? '+' : '';
    el.textContent = label + ' ' + sign + delta;
    el.classList.add(delta > 0 ? 'delta-up' : (delta < 0 ? 'delta-down' : 'delta-flat'));
}

function updateOverviewCard(id, currentValue, previous24hValue, previousWeekValue, degraded) {
    setOverviewStat('stat-' + id, currentValue, degraded);
    setOverviewDelta('stat-' + id + '-delta-24', currentValue, previous24hValue, 'prev 24h', degraded);
    setOverviewDelta('stat-' + id + '-delta-week', currentValue, previousWeekValue, 'last wk', degraded);
}

function renderTrendChart(trend, degraded) {
    var chart = document.getElementById('overview-trend-chart');
    if (!chart) return;

    if (degraded) {
        chart.innerHTML = '<div class="trend-empty">Trend unavailable</div>';
        return;
    }
    if (!trend || trend.length === 0) {
        chart.innerHTML = '<div class="trend-empty">No alert trend data</div>';
        return;
    }

    var maxCount = Math.max.apply(null, trend.map(function (bucket) { return Number(bucket.count || 0); })) || 1;
    var barSlot = 100 / trend.length;
    var bars = trend.map(function (bucket, index) {
        var count = Number(bucket.count || 0);
        var height = count ? Math.max(3, (count / maxCount) * 50) : 0;
        var x = index * barSlot + 0.25;
        var y = 56 - height;
        var width = Math.max(1.8, barSlot - 0.5);
        return '<rect class="trend-bar" x="' + x.toFixed(2) + '" y="' + y.toFixed(2) + '" width="' + width.toFixed(2) + '" height="' + height.toFixed(2) + '"><title>' + esc(count + ' alerts at ' + formatTime(bucket.start)) + '</title></rect>';
    }).join('');
    var first = trend[0] ? formatTime(trend[0].start) : '';
    var last = trend[trend.length - 1] ? formatTime(trend[trend.length - 1].end) : '';

    chart.innerHTML =
        '<svg class="trend-svg" viewBox="0 0 100 64" preserveAspectRatio="none" aria-hidden="true">' +
        '<line class="trend-axis" x1="0" y1="56" x2="100" y2="56"></line>' + bars +
        '</svg>' +
        '<div class="trend-caption"><span>' + esc(first) + '</span><span>' + esc(last) + '</span></div>';
}

function openOverviewAlertFilter(severity) {
    var severityFilter = document.getElementById('alert-severity-filter');
    var hoursFilter = document.getElementById('alert-hours-filter');
    var ruleFilter = document.getElementById('alert-rule-filter');
    if (severityFilter) severityFilter.value = severity || '';
    if (hoursFilter) hoursFilter.value = '24';
    if (ruleFilter) ruleFilter.value = '';
    showPage('alerts');
}

async function loadOverview() {
    var tbody = document.getElementById('top-rules-body');
    var notice = document.getElementById('overview-notice');
    notice.hidden = true;
    notice.textContent = '';
    tbody.innerHTML = '<tr><td colspan="3" class="loading"><div class="spinner"></div></td></tr>';

    var statsResult = await overviewFetch('/api/alerts/stats?hours=24&includeTrend=true&includeComparisons=true');
    var stats = statsResult.ok ? statsResult.data : { totalAlerts: 0, bySeverity: {}, topRules: [] };

    if (!statsResult.ok) {
        notice.textContent = 'Overview is partially unavailable: failed to load alert statistics.';
        notice.hidden = false;
    }

    var bySeverity = stats.bySeverity || {};
    var previous24h = stats.comparisons && stats.comparisons.previous24h ? stats.comparisons.previous24h : {};
    var previous24hSeverity = previous24h.bySeverity || {};
    var previousWeek = stats.comparisons && stats.comparisons.previousWeek ? stats.comparisons.previousWeek : {};
    var previousWeekSeverity = previousWeek.bySeverity || {};

    updateOverviewCard('total', stats.totalAlerts, previous24h.totalAlerts, previousWeek.totalAlerts, !statsResult.ok);
    updateOverviewCard('critical', bySeverity.critical, previous24hSeverity.critical, previousWeekSeverity.critical, !statsResult.ok);
    updateOverviewCard('high', bySeverity.high, previous24hSeverity.high, previousWeekSeverity.high, !statsResult.ok);
    updateOverviewCard('medium', bySeverity.medium, previous24hSeverity.medium, previousWeekSeverity.medium, !statsResult.ok);
    renderTrendChart(stats.trend || [], !statsResult.ok);

    if (!statsResult.ok) {
        tbody.innerHTML = emptyTableRow(3, 'Alert statistics unavailable', statsResult.error.message);
        return;
    }

    var topRules = stats.topRules || [];
    if (!topRules.length) {
        tbody.innerHTML = emptyTableRow(3, 'No alerts in the last 24 hours', 'New CloudTrail detections will appear here.');
        return;
    }

    tbody.innerHTML = topRules.map(function (rule) {
        var severity = rule.severity ? severityBadge(rule.severity) : '<span class="badge badge-muted">Unknown</span>';
        return '<tr><td><div class="cell-primary">' + esc(rule.rule || 'Unknown rule') + '</div></td>' +
            '<td>' + severity + '</td>' +
            '<td class="cell-numeric">' + esc(rule.count || 0) + '</td></tr>';
    }).join('');
}
