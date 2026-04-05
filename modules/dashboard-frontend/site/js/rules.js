/**
 * rules.js — Sigma Rules CRUD with client-side sort and search.
 *
 * Globals defined here:
 *   loadRules(), sortRules(), renderRulesTable(),
 *   editRule(), newRule(), saveRule(), deleteCurrentRule(), backToRulesList()
 *
 * Depends on: api() (api.js), toast() / showDialog() / esc() / escAttr() (ui.js)
 */
'use strict';

var currentRuleKey = null;
var rulesCache     = [];
var rulesSortField = 'title';
var rulesSortDir   = 'asc';

// -------------------------------------------------------
// Load & Render
// -------------------------------------------------------

async function loadRules() {
    document.getElementById('rules-list-view').style.display = '';
    document.getElementById('rules-edit-view').style.display = 'none';

    var tbody = document.getElementById('rules-body');
    tbody.innerHTML = '<tr><td colspan="5" class="loading"><div class="spinner"></div></td></tr>';

    try {
        var data = await api('/api/rules');
        rulesCache = data.rules || [];
        renderRulesTable();
    } catch (e) {
        tbody.innerHTML = '<tr><td colspan="5" style="color:var(--critical);">Failed to load rules: ' + esc(e.message) + '</td></tr>';
    }
}

function sortRules(thEl, field) {
    if (rulesSortField === field) {
        rulesSortDir = rulesSortDir === 'asc' ? 'desc' : 'asc';
    } else {
        rulesSortField = field;
        rulesSortDir = 'asc';
    }
    thEl.closest('thead').querySelectorAll('th.sortable').forEach(function (h) { h.classList.remove('asc', 'desc'); });
    thEl.classList.add(rulesSortDir);
    renderRulesTable();
}

function renderRulesTable() {
    var tbody  = document.getElementById('rules-body');
    var search = (document.getElementById('rules-search').value || '').toLowerCase();

    var filtered = rulesCache;
    if (search) {
        filtered = rulesCache.filter(function (r) {
            return (r.title || '').toLowerCase().includes(search) ||
                   (r.level || '').toLowerCase().includes(search) ||
                   (r.status || '').toLowerCase().includes(search);
        });
    }

    filtered.sort(function (a, b) {
        var va = a[rulesSortField] || '';
        var vb = b[rulesSortField] || '';
        if (rulesSortField === 'lastModified') {
            va = new Date(va).getTime() || 0;
            vb = new Date(vb).getTime() || 0;
            return rulesSortDir === 'asc' ? va - vb : vb - va;
        }
        var cmp = String(va).localeCompare(String(vb));
        return rulesSortDir === 'asc' ? cmp : -cmp;
    });

    tbody.innerHTML = '';
    if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:2rem;">' +
            (rulesCache.length === 0 ? 'No rules found. Click "+ New Rule" to create one.' : 'No rules match your search.') + '</td></tr>';
        return;
    }

    filtered.forEach(function (r) {
        var tr = document.createElement('tr');
        tr.innerHTML =
            '<td>' + esc(r.title) + '</td>' +
            '<td><span class="badge badge-' + (r.level || 'info') + '">' + esc(r.level || '?') + '</span></td>' +
            '<td>' + esc(r.status || '') + '</td>' +
            '<td>' + new Date(r.lastModified).toLocaleString() + '</td>' +
            '<td><button class="btn btn-secondary btn-sm" onclick="editRule(\'' + escAttr(r.key) + '\')">Edit</button></td>';
        tbody.appendChild(tr);
    });
}

// -------------------------------------------------------
// Edit / New / Save / Delete
// -------------------------------------------------------

async function editRule(key) {
    document.getElementById('rules-list-view').style.display = 'none';
    document.getElementById('rules-edit-view').style.display = '';
    document.getElementById('editor-title').textContent = key;
    document.getElementById('delete-rule-btn').style.display = '';
    currentRuleKey = key;

    try {
        var data = await api('/api/rules/' + encodeURIComponent(key));
        document.getElementById('yaml-editor').value = data.content;
    } catch (e) {
        toast('Failed to load rule: ' + e.message, 'error');
    }
}

function newRule() {
    document.getElementById('rules-list-view').style.display = 'none';
    document.getElementById('rules-edit-view').style.display = '';
    document.getElementById('editor-title').textContent = 'New Rule';
    document.getElementById('delete-rule-btn').style.display = 'none';
    currentRuleKey = null;

    document.getElementById('yaml-editor').value =
        'title: New Detection Rule\n' +
        'id: \n' +
        'status: experimental\n' +
        'level: medium\n' +
        'description: Describe what this rule detects\n' +
        'logsource:\n' +
        '  product: aws\n' +
        '  service: cloudtrail\n' +
        'detection:\n' +
        '  selection:\n' +
        '    eventSource: \n' +
        '    eventName: \n' +
        '  condition: selection\n';
}

async function saveRule() {
    var content = document.getElementById('yaml-editor').value;
    var key = currentRuleKey;

    if (!key) {
        key = await showDialog('Save Rule', 'Enter a filename for the rule:', { input: true, placeholder: 'my-detection.yaml', confirmText: 'Save' });
        if (!key) return;
        if (!key.endsWith('.yaml') && !key.endsWith('.yml')) key += '.yaml';
    }

    try {
        await api('/api/rules/' + encodeURIComponent(key), { method: 'PUT', body: content });
        currentRuleKey = key;
        document.getElementById('editor-title').textContent = key;
        document.getElementById('delete-rule-btn').style.display = '';
        toast('Rule saved successfully');
    } catch (e) {
        toast('Failed to save: ' + e.message, 'error');
    }
}

async function deleteCurrentRule() {
    if (!currentRuleKey) return;
    var ok = await showDialog('Delete Rule', 'Delete rule "' + currentRuleKey + '"? This cannot be undone.', { confirmText: 'Delete', danger: true });
    if (!ok) return;

    try {
        await api('/api/rules/' + encodeURIComponent(currentRuleKey), { method: 'DELETE' });
        toast('Rule deleted');
        loadRules();
    } catch (e) {
        toast('Failed to delete: ' + e.message, 'error');
    }
}

function backToRulesList() {
    loadRules();
}
