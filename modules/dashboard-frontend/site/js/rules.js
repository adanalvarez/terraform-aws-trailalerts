/**
 * rules.js - Sigma Rules CRUD with workflow-aware editor state.
 *
 * Globals defined here:
 *   loadRules(), sortRules(), renderRulesTable(), editRule(), newRule(),
 *   validateCurrentRule(), testCurrentRule(), saveRule(), deleteCurrentRule(),
 *   toggleRuleSelection(), toggleVisibleRulesSelection(), bulkSetRuleState(),
 *   bulkDeleteRules(), cloneRule(), cloneCurrentRule(), toggleRuleState(),
 *   toggleCurrentRuleState(), loadRuleVersion(), backToRulesList()
 *
 * Depends on: api() (api.js), RuleCodeEditor (rule_editor.js), and UI helpers.
 */
'use strict';

var currentRuleKey = null;
var currentRuleEnabled = true;
var currentRuleVersionId = null;
var lastSavedContent = '';
var lastSavedAt = null;
var rulesCache = [];
var selectedRules = {};
var rulesSortField = 'title';
var rulesSortDir = 'asc';
var ruleEditor = null;
var ruleValidation = null;
var ruleTestResult = null;
var ruleValidationTimer = null;
var ruleValidationRequestId = 0;
var ruleIsValidating = false;
var ruleIsSaving = false;

var defaultRuleTemplate = [
    'title: New Detection Rule',
    'id: ',
    'status: experimental',
    'level: medium',
    'description: Describe what this rule detects',
    'logsource:',
    '  product: aws',
    '  service: cloudtrail',
    'detection:',
    '  selection:',
    '    eventSource: ',
    '    eventName: ',
    '  condition: selection',
    '',
].join('\n');

var defaultSampleEvent = JSON.stringify({
    eventSource: 'iam.amazonaws.com',
    eventName: 'CreateUser',
    userIdentity: {
        type: 'IAMUser',
        arn: 'arn:aws:iam::123456789012:user/example',
    },
    sourceIPAddress: '203.0.113.10',
    awsRegion: 'us-east-1',
}, null, 2);

// -------------------------------------------------------
// Load & Render
// -------------------------------------------------------

async function loadRules() {
    setHidden('rules-list-view', false);
    setHidden('rules-edit-view', true);

    var tbody = document.getElementById('rules-body');
    selectedRules = {};
    updateBulkRuleActions([]);
    tbody.innerHTML = '<tr><td colspan="7" class="loading"><div class="spinner"></div></td></tr>';

    try {
        var data = await api('/api/rules');
        rulesCache = data.rules || [];
        renderRulesTable();
    } catch (e) {
        tbody.innerHTML = emptyTableRow(7, 'Failed to load rules', e.message);
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
    var tbody = document.getElementById('rules-body');
    var filtered = getFilteredRules();

    tbody.innerHTML = '';
    if (filtered.length === 0) {
        tbody.innerHTML = rulesCache.length === 0
            ? emptyTableRow(7, 'No rules found', 'Create a Sigma rule to start alerting on CloudTrail activity.')
            : emptyTableRow(7, 'No rules match your search', 'Try another title, severity, status, or state.');
        updateBulkRuleActions(filtered);
        return;
    }

    filtered.forEach(function (rule) {
        var enabled = rule.enabled !== false;
        var stateButton = enabled ? 'Disable' : 'Enable';
        var selectionId = ruleSelectionId(rule.key, enabled);
        var checked = selectedRules[selectionId] ? ' checked' : '';
        var tr = document.createElement('tr');
        tr.innerHTML =
            '<td class="bulk-select-cell"><input type="checkbox" class="rule-select-checkbox" data-rule-select="true" data-key="' + escAttr(rule.key) + '" data-enabled="' + escAttr(String(enabled)) + '" aria-label="Select ' + escAttr(rule.title || rule.key || 'rule') + '"' + checked + '></td>' +
            '<td><div class="cell-primary">' + esc(rule.title || rule.key || 'Untitled rule') + '</div><div class="cell-secondary mono">' + esc(rule.key || '') + '</div></td>' +
            '<td>' + severityBadge(rule.level) + '</td>' +
            '<td>' + statusBadge(rule.status || '') + '</td>' +
            '<td>' + ruleStateBadge(enabled) + '</td>' +
            '<td class="cell-nowrap">' + esc(formatTime(rule.lastModified)) + '</td>' +
            '<td><div class="rule-actions"><button class="btn btn-secondary btn-sm" data-action="edit-rule" data-key="' + escAttr(rule.key) + '" data-enabled="' + escAttr(String(enabled)) + '">Edit</button>' +
            '<button class="btn btn-secondary btn-sm" data-action="clone-rule" data-key="' + escAttr(rule.key) + '" data-enabled="' + escAttr(String(enabled)) + '">Clone</button>' +
            '<button class="btn btn-secondary btn-sm" data-action="toggle-rule-state" data-key="' + escAttr(rule.key) + '" data-enabled="' + escAttr(String(enabled)) + '">' + stateButton + '</button></div></td>';
        tbody.appendChild(tr);
    });
    updateBulkRuleActions(filtered);
}

function ruleStateBadge(enabled) {
    return '<span class="badge ' + (enabled ? 'badge-success' : 'badge-muted') + '">' + (enabled ? 'Enabled' : 'Disabled') + '</span>';
}

function getFilteredRules() {
    var search = (document.getElementById('rules-search').value || '').toLowerCase();
    var filtered = rulesCache;
    if (search) {
        filtered = rulesCache.filter(function (rule) {
            return (rule.title || '').toLowerCase().includes(search) ||
                   (rule.level || '').toLowerCase().includes(search) ||
                   (rule.status || '').toLowerCase().includes(search) ||
                   (rule.enabled ? 'enabled' : 'disabled').includes(search);
        });
    }

    return filtered.slice().sort(function (a, b) {
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
}

function ruleSelectionId(key, enabled) {
    return encodeURIComponent(key || '') + '::' + (enabled ? 'enabled' : 'disabled');
}

function getSelectedRules() {
    return Object.keys(selectedRules).map(function (id) { return selectedRules[id]; });
}

function toggleRuleSelection(key, enabled, checked) {
    var normalizedEnabled = enabled !== false;
    var id = ruleSelectionId(key, normalizedEnabled);
    if (checked) selectedRules[id] = { key: key, enabled: normalizedEnabled };
    else delete selectedRules[id];
    updateBulkRuleActions(getFilteredRules());
}

function toggleVisibleRulesSelection(checked) {
    getFilteredRules().forEach(function (rule) {
        toggleRuleSelection(rule.key, rule.enabled !== false, checked);
    });
    renderRulesTable();
}

function updateBulkRuleActions(visibleRules) {
    var selected = getSelectedRules();
    var countEl = document.getElementById('rules-selected-count');
    if (countEl) countEl.textContent = selected.length + ' selected';

    ['bulk-enable-rules-btn', 'bulk-disable-rules-btn', 'bulk-delete-rules-btn'].forEach(function (id) {
        setButtonState(id, selected.length === 0);
    });

    var selectAll = document.getElementById('rules-select-all');
    if (!selectAll) return;
    var visible = visibleRules || [];
    var selectedVisible = visible.filter(function (rule) {
        return !!selectedRules[ruleSelectionId(rule.key, rule.enabled !== false)];
    }).length;
    selectAll.checked = visible.length > 0 && selectedVisible === visible.length;
    selectAll.indeterminate = selectedVisible > 0 && selectedVisible < visible.length;
}

// -------------------------------------------------------
// Editor State
// -------------------------------------------------------

function ensureRuleEditor() {
    if (ruleEditor) return ruleEditor;
    ruleEditor = RuleCodeEditor.create({
        textareaId: 'yaml-editor',
        highlightId: 'yaml-highlight',
        gutterId: 'yaml-line-numbers',
        canvasId: 'yaml-editor-canvas',
        onChange: handleRuleEditorChange,
        onSave: saveRule,
    });
    return ruleEditor;
}

function getRuleContent() {
    return ensureRuleEditor().getValue();
}

function setRuleContent(content) {
    ensureRuleEditor().setValue(content || '');
}

function isRuleDirty() {
    return getRuleContent() !== lastSavedContent;
}

function handleRuleEditorChange() {
    ruleTestResult = null;
    scheduleRuleValidation();
    updateRuleEditorState();
}

function setStatePill(id, state, text) {
    var el = document.getElementById(id);
    if (!el) return;
    el.className = 'state-pill state-' + state;
    el.textContent = text;
}

function setButtonState(id, disabled) {
    var button = document.getElementById(id);
    if (button) button.disabled = !!disabled;
}

function updateWorkflowSteps() {
    var dirty = isRuleDirty();
    var valid = ruleValidation && ruleValidation.valid;
    var tested = ruleTestResult && ruleTestResult.valid && ruleTestResult.matched !== null;
    document.querySelectorAll('.workflow-step').forEach(function (step) {
        var name = step.dataset.step;
        step.classList.remove('active', 'done', 'error');
        if (name === 'write' && dirty) step.classList.add('active');
        if (name === 'validate' && valid) step.classList.add('done');
        if (name === 'validate' && ruleValidation && !ruleValidation.valid) step.classList.add('error');
        if (name === 'test' && tested) step.classList.add('done');
        if (name === 'save' && !dirty && currentRuleKey) step.classList.add('done');
        if (name === 'deploy' && !dirty && currentRuleKey && currentRuleEnabled) step.classList.add('done');
    });
}

function updateRuleEditorState() {
    var dirty = isRuleDirty();
    var valid = ruleValidation && ruleValidation.valid;
    var hasValidation = !!ruleValidation;
    var validationText = ruleIsValidating ? 'Validating' : (valid ? 'Valid' : (hasValidation ? 'Invalid' : 'Not validated'));

    setStatePill('rule-dirty-state', dirty ? 'dirty' : 'muted', dirty ? 'Unsaved changes' : 'Clean');
    setStatePill('rule-enabled-state', currentRuleEnabled ? 'valid' : 'muted', currentRuleEnabled ? 'Enabled' : 'Disabled');
    setStatePill('rule-validation-state', ruleIsValidating ? 'warning' : (valid ? 'valid' : (hasValidation ? 'error' : 'muted')), validationText);
    setStatePill('rule-test-state', ruleTestResult ? (ruleTestResult.matched ? 'valid' : 'warning') : 'muted', ruleTestResult ? (ruleTestResult.matched ? 'Matched sample' : 'No match') : 'Not tested');

    setButtonState('save-rule-btn', ruleIsSaving || ruleIsValidating || !valid || !dirty);
    setButtonState('test-rule-btn', ruleIsValidating || (hasValidation && !valid));
    setHidden('delete-rule-btn', !currentRuleKey);
    setHidden('toggle-rule-state-btn', !currentRuleKey);

    var toggleButton = document.getElementById('toggle-rule-state-btn');
    if (toggleButton) toggleButton.textContent = currentRuleEnabled ? 'Disable' : 'Enable';

    var saveButton = document.getElementById('save-rule-btn');
    if (saveButton) saveButton.textContent = currentRuleEnabled ? 'Save and deploy' : 'Save disabled rule';

    var lastSaved = document.getElementById('rule-last-saved');
    if (lastSaved) lastSaved.textContent = lastSavedAt ? 'Last saved ' + formatTime(lastSavedAt) : 'Not saved yet';

    var saveStatus = document.getElementById('rule-save-status');
    if (saveStatus) {
        if (ruleIsSaving) saveStatus.textContent = currentRuleEnabled ? 'Saving and deploying rule...' : 'Saving disabled rule...';
        else if (!valid) saveStatus.textContent = hasValidation ? 'Fix validation errors before saving.' : 'Validate the rule before saving.';
        else if (dirty && currentRuleEnabled) saveStatus.textContent = 'Valid rule with unsaved changes. Save will deploy it to the analyzer bucket.';
        else if (dirty) saveStatus.textContent = 'Valid disabled rule with unsaved changes. Save keeps it out of analyzer matching.';
        else saveStatus.textContent = currentRuleEnabled ? 'Saved and deployed.' : 'Saved as disabled. Analyzer will not load it.';
    }

    updateWorkflowSteps();
}

function scheduleRuleValidation() {
    clearTimeout(ruleValidationTimer);
    ruleValidationTimer = setTimeout(function () { validateCurrentRule(false); }, 450);
}

function renderValidationPanel() {
    var panel = document.getElementById('rule-validation-panel');
    if (!panel) return;

    if (ruleIsValidating) {
        panel.innerHTML = '<div class="validation-empty">Validating Sigma YAML...</div>';
        return;
    }
    if (!ruleValidation) {
        panel.innerHTML = '<div class="validation-empty">Validation runs automatically as you type.</div>';
        return;
    }

    var items = [];
    (ruleValidation.errors || []).forEach(function (error) {
        items.push('<li class="validation-error"><span>' + esc(error.line ? 'Line ' + error.line : 'Rule') + '</span>' + esc(error.message) + '</li>');
    });
    (ruleValidation.warnings || []).forEach(function (warning) {
        items.push('<li class="validation-warning"><span>' + esc(warning.line ? 'Line ' + warning.line : 'Hint') + '</span>' + esc(warning.message) + '</li>');
    });

    if (items.length === 0) {
        panel.innerHTML = '<div class="validation-ok">Rule is valid and ready to test.</div>';
        return;
    }
    panel.innerHTML = '<ul class="validation-list">' + items.join('') + '</ul>';
}

function renderSchemaHints() {
    var panel = document.getElementById('rule-schema-hints');
    if (!panel) return;

    var baseHints = [
        'Required: title, logsource, detection.',
        'Detection requires at least one selection block and condition.',
        'CloudTrail fields support dotted paths such as userIdentity.type.',
        'Supported test operators: contains, startswith, endswith, re.',
    ];
    var dynamicHints = ruleValidation ? (ruleValidation.hints || []) : [];
    panel.innerHTML = baseHints.concat(dynamicHints).map(function (hint) {
        return '<div class="hint-item">' + esc(hint) + '</div>';
    }).join('');
}

function renderRuleMetadata() {
    var list = document.getElementById('rule-metadata');
    if (!list) return;
    var metadata = ruleValidation && ruleValidation.metadata ? ruleValidation.metadata : {};
    var rows = [
        ['Title', metadata.title || 'Unknown'],
        ['ID', metadata.id || 'Not set'],
        ['Status', metadata.status || 'Not set'],
        ['Level', metadata.level || 'info'],
        ['Runtime', currentRuleEnabled ? 'Enabled' : 'Disabled'],
        ['Condition', metadata.condition || 'Not set'],
        ['Blocks', (ruleValidation && ruleValidation.blocks || []).join(', ') || 'None'],
    ];
    list.innerHTML = rows.map(function (row) {
        return '<dt>' + esc(row[0]) + '</dt><dd>' + esc(row[1]) + '</dd>';
    }).join('');
}

function renderRuleEditorDetails() {
    var markers = [];
    if (ruleValidation) {
        (ruleValidation.errors || []).forEach(function (error) { markers.push(Object.assign({ severity: 'error' }, error)); });
        (ruleValidation.warnings || []).forEach(function (warning) { markers.push(Object.assign({ severity: 'warning' }, warning)); });
    }
    ensureRuleEditor().setMarkers(markers);
    renderValidationPanel();
    renderSchemaHints();
    renderRuleMetadata();
}

async function validateCurrentRule(showToast) {
    var requestId = ++ruleValidationRequestId;
    ruleIsValidating = true;
    updateRuleEditorState();
    renderValidationPanel();

    try {
        var data = await api('/api/rules/validate', { method: 'POST', body: getRuleContent() });
        if (requestId !== ruleValidationRequestId) return data;
        ruleValidation = data;
        if (showToast) toast(data.valid ? 'Rule is valid' : 'Rule has validation errors', data.valid ? 'success' : 'error');
        return data;
    } catch (e) {
        if (requestId !== ruleValidationRequestId) return null;
        ruleValidation = { valid: false, errors: [{ message: e.message, line: 1 }], warnings: [], hints: [] };
        if (showToast) toast('Validation failed: ' + e.message, 'error');
        return ruleValidation;
    } finally {
        if (requestId === ruleValidationRequestId) {
            ruleIsValidating = false;
            renderRuleEditorDetails();
            updateRuleEditorState();
        }
    }
}

// -------------------------------------------------------
// Test / History
// -------------------------------------------------------

async function testCurrentRule() {
    var validation = await validateCurrentRule(false);
    if (!validation || !validation.valid) {
        toast('Fix validation errors before testing', 'error');
        return;
    }

    var resultEl = document.getElementById('rule-test-result');
    resultEl.innerHTML = '<div class="validation-empty">Running rule test...</div>';
    try {
        var data = await api('/api/rules/test', {
            method: 'POST',
            body: JSON.stringify({ content: getRuleContent(), sampleEvent: document.getElementById('rule-test-event').value }),
        });
        ruleTestResult = data;
        renderRuleTestResult(data);
        updateRuleEditorState();
    } catch (e) {
        ruleTestResult = { valid: false, matched: null };
        resultEl.innerHTML = '<div class="validation-error-block">' + esc(e.message) + '</div>';
        updateRuleEditorState();
    }
}

function renderRuleTestResult(data) {
    var resultEl = document.getElementById('rule-test-result');
    if (!resultEl) return;
    var statusClass = data.matched ? 'test-match' : (data.matched === false ? 'test-no-match' : 'test-neutral');
    var blocks = (data.evaluatedBlocks || []).map(function (block) {
        return '<div class="test-block"><strong>' + esc(block.block) + '</strong><span>' + (block.matched ? 'matched' : 'not matched') + '</span></div>';
    }).join('');
    var errors = (data.errors || []).map(function (error) { return '<div class="validation-error-block">' + esc(error.message) + '</div>'; }).join('');
    resultEl.innerHTML = '<div class="test-summary ' + statusClass + '">' + esc(data.summary || 'Test complete') + '</div>' + errors + blocks;
}

async function loadRuleHistory(key) {
    var historyEl = document.getElementById('rule-version-history');
    if (!historyEl) return;
    if (!key) {
        historyEl.innerHTML = '<div class="history-empty">History starts after the first save.</div>';
        return;
    }

    historyEl.innerHTML = '<div class="history-empty">Loading history...</div>';
    try {
        var data = await api('/api/rules/history?key=' + encodeURIComponent(key) + '&enabled=' + encodeURIComponent(String(currentRuleEnabled)));
        var versions = data.versions || [];
        if (versions.length === 0) {
            historyEl.innerHTML = '<div class="history-empty">No previous versions yet.</div>';
            return;
        }
        historyEl.innerHTML = versions.map(function (version) {
            var current = version.versionId === currentRuleVersionId || version.isLatest;
            return '<div class="history-item">' +
                '<div><strong>' + esc(formatTime(version.lastModified)) + '</strong><span class="history-meta">' + esc(current ? 'Current' : (version.versionId || '').slice(0, 16)) + '</span></div>' +
                '<button class="btn btn-secondary btn-sm" data-action="load-rule-version" data-version-id="' + escAttr(version.versionId) + '">Load</button>' +
                '</div>';
        }).join('');
    } catch (e) {
        historyEl.innerHTML = '<div class="history-empty">' + esc(e.message) + '</div>';
    }
}

async function loadRuleVersion(versionId) {
    if (!currentRuleKey || !versionId) return;
    if (isRuleDirty()) {
        var ok = await showDialog('Load Version', 'Loading a previous version will replace the unsaved editor content.', { confirmText: 'Load version' });
        if (!ok) return;
    }

    try {
        var data = await api('/api/rules/' + encodeURIComponent(currentRuleKey) + '?versionId=' + encodeURIComponent(versionId) + '&enabled=' + encodeURIComponent(String(currentRuleEnabled)));
        setRuleContent(data.content || '');
        currentRuleVersionId = data.versionId || versionId;
        ruleTestResult = null;
        document.getElementById('rule-test-result').innerHTML = '';
        await validateCurrentRule(false);
        toast('Version loaded. Save and deploy to make it current.');
    } catch (e) {
        toast('Failed to load version: ' + e.message, 'error');
    }
}

// -------------------------------------------------------
// Edit / New / Save / Delete
// -------------------------------------------------------

async function editRule(key, enabled) {
    setHidden('rules-list-view', true);
    setHidden('rules-edit-view', false);
    ensureRuleEditor();
    document.getElementById('editor-title').textContent = key;
    currentRuleKey = key;
    currentRuleEnabled = enabled !== false;
    ruleValidation = null;
    ruleTestResult = null;
    document.getElementById('rule-test-event').value = defaultSampleEvent;
    document.getElementById('rule-test-result').innerHTML = '';

    try {
        var data = await api('/api/rules/' + encodeURIComponent(key) + '?enabled=' + encodeURIComponent(String(currentRuleEnabled)));
        currentRuleEnabled = data.enabled !== false;
        currentRuleVersionId = data.versionId || null;
        lastSavedContent = data.content || '';
        lastSavedAt = data.lastModified || null;
        setRuleContent(data.content || '');
        await validateCurrentRule(false);
        loadRuleHistory(key);
        ensureRuleEditor().focus();
    } catch (e) {
        toast('Failed to load rule: ' + e.message, 'error');
    }
    updateRuleEditorState();
}

function newRule() {
    setHidden('rules-list-view', true);
    setHidden('rules-edit-view', false);
    ensureRuleEditor();
    document.getElementById('editor-title').textContent = 'New Rule';
    currentRuleKey = null;
    currentRuleEnabled = true;
    currentRuleVersionId = null;
    lastSavedContent = '';
    lastSavedAt = null;
    ruleValidation = null;
    ruleTestResult = null;
    document.getElementById('rule-test-event').value = defaultSampleEvent;
    document.getElementById('rule-test-result').innerHTML = '';
    setRuleContent(defaultRuleTemplate);
    renderRuleEditorDetails();
    validateCurrentRule(false);
    loadRuleHistory(null);
    ensureRuleEditor().focus();
    updateRuleEditorState();
}

async function saveRule() {
    if (ruleIsSaving) return;
    var validation = await validateCurrentRule(false);
    if (!validation || !validation.valid) {
        toast('Fix validation errors before saving', 'error');
        return;
    }

    var content = getRuleContent();
    var key = currentRuleKey;

    if (!key) {
        key = await showDialog('Save Rule', 'Enter a filename for the rule:', { input: true, placeholder: 'my-detection.yaml', confirmText: 'Save and deploy' });
        if (!key) return;
        if (!key.endsWith('.yaml') && !key.endsWith('.yml')) key += '.yaml';
    }

    ruleIsSaving = true;
    updateRuleEditorState();
    try {
        var response = await api('/api/rules/' + encodeURIComponent(key) + '?enabled=' + encodeURIComponent(String(currentRuleEnabled)), { method: 'PUT', body: content });
        currentRuleKey = response.key || key;
        currentRuleEnabled = response.enabled !== false;
        currentRuleVersionId = null;
        lastSavedContent = content;
        lastSavedAt = new Date().toISOString();
        document.getElementById('editor-title').textContent = currentRuleKey;
        toast(currentRuleEnabled ? 'Rule saved and deployed' : 'Disabled rule saved');
        loadRuleHistory(currentRuleKey);
    } catch (e) {
        toast('Failed to save: ' + e.message, 'error');
    } finally {
        ruleIsSaving = false;
        updateRuleEditorState();
    }
}

async function cloneRule(key, enabled) {
    var normalizedEnabled = enabled !== false;
    try {
        var data = await api('/api/rules/' + encodeURIComponent(key) + '?enabled=' + encodeURIComponent(String(normalizedEnabled)));
        setHidden('rules-list-view', true);
        setHidden('rules-edit-view', false);
        ensureRuleEditor();
        currentRuleKey = null;
        currentRuleEnabled = data.enabled !== false;
        currentRuleVersionId = null;
        lastSavedContent = '';
        lastSavedAt = null;
        ruleValidation = null;
        ruleTestResult = null;
        document.getElementById('editor-title').textContent = 'Clone of ' + key;
        document.getElementById('rule-test-event').value = defaultSampleEvent;
        document.getElementById('rule-test-result').innerHTML = '';
        setRuleContent(data.content || '');
        renderRuleEditorDetails();
        validateCurrentRule(false);
        loadRuleHistory(null);
        ensureRuleEditor().focus();
        updateRuleEditorState();
        toast('Rule cloned in editor. Review title and id before saving.');
    } catch (e) {
        toast('Failed to clone rule: ' + e.message, 'error');
    }
}

async function cloneCurrentRule() {
    if (!getRuleContent().trim()) return;
    var sourceLabel = currentRuleKey || 'current draft';
    currentRuleKey = null;
    currentRuleVersionId = null;
    lastSavedContent = '';
    lastSavedAt = null;
    document.getElementById('editor-title').textContent = 'Clone of ' + sourceLabel;
    loadRuleHistory(null);
    updateRuleEditorState();
    toast('Cloned as a new draft. Review title and id before saving.');
}

async function bulkSetRuleState(enabled) {
    var selected = getSelectedRules();
    var candidates = selected.filter(function (rule) { return rule.enabled !== enabled; });
    if (selected.length === 0) return;
    if (candidates.length === 0) {
        toast(enabled ? 'Selected rules are already enabled' : 'Selected rules are already disabled');
        return;
    }

    var ok = await showDialog(
        enabled ? 'Enable Rules' : 'Disable Rules',
        (enabled ? 'Enable ' : 'Disable ') + candidates.length + ' selected rule' + (candidates.length !== 1 ? 's' : '') + '?',
        { confirmText: enabled ? 'Enable rules' : 'Disable rules', danger: !enabled }
    );
    if (!ok) return;

    var failures = [];
    for (var index = 0; index < candidates.length; index += 1) {
        var rule = candidates[index];
        try {
            await api('/api/rules/' + encodeURIComponent(rule.key) + '/state', {
                method: 'POST',
                body: JSON.stringify({ enabled: enabled }),
            });
        } catch (e) {
            failures.push(rule.key + ': ' + e.message);
        }
    }

    selectedRules = {};
    await loadRules();
    if (failures.length) toast('Some rules failed: ' + failures.slice(0, 2).join('; '), 'error');
    else toast(enabled ? 'Rules enabled' : 'Rules disabled');
}

async function bulkDeleteRules() {
    var selected = getSelectedRules();
    if (selected.length === 0) return;

    var ok = await showDialog(
        'Delete Rules',
        'Delete ' + selected.length + ' selected rule' + (selected.length !== 1 ? 's' : '') + '? Existing alert history is retained.',
        { confirmText: 'Delete rules', danger: true }
    );
    if (!ok) return;

    var failures = [];
    for (var index = 0; index < selected.length; index += 1) {
        var rule = selected[index];
        try {
            await api('/api/rules/' + encodeURIComponent(rule.key) + '?enabled=' + encodeURIComponent(String(rule.enabled)), { method: 'DELETE' });
        } catch (e) {
            failures.push(rule.key + ': ' + e.message);
        }
    }

    selectedRules = {};
    await loadRules();
    if (failures.length) toast('Some rules failed: ' + failures.slice(0, 2).join('; '), 'error');
    else toast('Rules deleted');
}

async function toggleRuleState(key, enabled) {
    var nextEnabled = !enabled;
    var title = nextEnabled ? 'Enable Rule' : 'Disable Rule';
    var message = nextEnabled
        ? 'Move "' + key + '" back to sigma_rules/ so the analyzer can match it on new CloudTrail files?'
        : 'Move "' + key + '" to disabled_sigma_rules/ so it remains editable but no longer matches new CloudTrail files?';
    var ok = await showDialog(title, message, { confirmText: nextEnabled ? 'Enable rule' : 'Disable rule', danger: !nextEnabled });
    if (!ok) return;

    try {
        var response = await api('/api/rules/' + encodeURIComponent(key) + '/state', {
            method: 'POST',
            body: JSON.stringify({ enabled: nextEnabled }),
        });
        toast(response.message || (nextEnabled ? 'Rule enabled' : 'Rule disabled'));
        if (currentRuleKey === key) {
            currentRuleEnabled = response.enabled !== false;
            currentRuleVersionId = null;
            loadRuleHistory(currentRuleKey);
            renderRuleEditorDetails();
            updateRuleEditorState();
        }
        if (!document.getElementById('rules-list-view').hidden) loadRules();
    } catch (e) {
        toast('Failed to change rule state: ' + e.message, 'error');
    }
}

async function toggleCurrentRuleState() {
    if (!currentRuleKey) return;
    if (isRuleDirty()) {
        toast('Save or discard editor changes before changing rule state', 'error');
        return;
    }
    await toggleRuleState(currentRuleKey, currentRuleEnabled);
}

async function deleteCurrentRule() {
    if (!currentRuleKey) return;
    var ok = await showDialog(
        'Confirm Delete',
        'Delete Sigma rule "' + currentRuleKey + '" from the deployed rule bucket? Existing alert history is retained.',
        { confirmText: 'Delete rule', danger: true }
    );
    if (!ok) return;

    try {
        await api('/api/rules/' + encodeURIComponent(currentRuleKey) + '?enabled=' + encodeURIComponent(String(currentRuleEnabled)), { method: 'DELETE' });
        toast('Rule deleted');
        currentRuleKey = null;
        loadRules();
    } catch (e) {
        toast('Failed to delete: ' + e.message, 'error');
    }
}

async function backToRulesList() {
    if (isRuleDirty()) {
        var ok = await showDialog('Unsaved Changes', 'Return to the rule library without saving your editor changes?', { confirmText: 'Discard changes' });
        if (!ok) return;
    }
    loadRules();
}
