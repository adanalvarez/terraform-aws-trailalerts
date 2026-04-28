/**
 * postprocessing.js - Postprocessing rules CRUD with workflow-aware JSON editor.
 *
 * Globals defined here:
 *   loadPostprocessing(), editPPFile(), newPostprocessingRule(),
 *   newPostprocessingFile(), validatePP(), savePP(), deletePPFile(),
 *   deleteCurrentPP(), backToPPList()
 *
 * Depends on: api() (api.js), RuleCodeEditor (rule_editor.js), and UI helpers.
 */
'use strict';

var ppCurrentKey = null;
var ppLastSavedContent = '';
var ppLastSavedAt = null;
var ppEditor = null;
var ppValidation = null;
var ppValidationTimer = null;
var ppValidationRequestId = 0;
var ppIsValidating = false;
var ppIsSaving = false;

var ppTemplates = {
    correlation: [{
        type: 'correlation',
        sigmaRuleTitle: '',
        lookFor: ['Related rule title'],
        windowMinutes: 10,
        adjustSeverity: 'high',
    }],
    threshold: [{
        type: 'threshold',
        sigmaRuleTitle: '',
        thresholdCount: 5,
        windowMinutes: 10,
        adjustSeverity: 'critical',
    }],
};

// -------------------------------------------------------
// Load & Render
// -------------------------------------------------------

async function loadPostprocessing() {
    setHidden('pp-list-view', false);
    setHidden('pp-edit-view', true);

    var corrBody = document.getElementById('correlation-body');
    var thrBody = document.getElementById('threshold-body');
    var filesBody = document.getElementById('pp-files-body');
    corrBody.innerHTML = thrBody.innerHTML = filesBody.innerHTML =
        '<tr><td colspan="6"><div class="loading"><div class="spinner"></div></div></td></tr>';

    try {
        var data = await api('/api/postprocessing');
        var correlationRules = data.correlationRules || [];
        var thresholdRules = data.thresholdRules || [];
        var files = data.files || [];

        corrBody.innerHTML = '';
        thrBody.innerHTML = '';
        filesBody.innerHTML = '';

        correlationRules.forEach(function (rule) {
            var lookFor = Array.isArray(rule.lookFor) ? rule.lookFor : (rule.lookFor ? [rule.lookFor] : []);
            var severity = rule.adjustSeverity || rule.severity_adjustment || '-';
            corrBody.innerHTML += '<tr>' +
                '<td><div class="cell-primary">' + esc(rule.sigmaRuleTitle || '') + '</div></td>' +
                '<td class="mono">' + esc(lookFor.join(', ')) + '</td>' +
                '<td class="cell-numeric">' + esc(rule.windowMinutes || '') + '</td>' +
                '<td>' + (severity === '-' ? '<span class="badge badge-muted">None</span>' : severityBadge(severity)) + '</td>' +
                '<td class="mono">' + esc(rule._file || '') + '</td>' +
                '<td><button class="btn btn-secondary btn-sm" data-action="edit-postprocessing" data-key="' + escAttr(rule._file || '') + '">Edit</button></td>' +
                '</tr>';
        });

        thresholdRules.forEach(function (rule) {
            var severity = rule.adjustSeverity || rule.severity_adjustment || '-';
            thrBody.innerHTML += '<tr>' +
                '<td><div class="cell-primary">' + esc(rule.sigmaRuleTitle || '') + '</div></td>' +
                '<td class="cell-numeric">' + esc(rule.thresholdCount || '') + '</td>' +
                '<td class="cell-numeric">' + esc(rule.windowMinutes || '') + '</td>' +
                '<td>' + (severity === '-' ? '<span class="badge badge-muted">None</span>' : severityBadge(severity)) + '</td>' +
                '<td class="mono">' + esc(rule._file || '') + '</td>' +
                '<td><button class="btn btn-secondary btn-sm" data-action="edit-postprocessing" data-key="' + escAttr(rule._file || '') + '">Edit</button></td>' +
                '</tr>';
        });

        if (corrBody.innerHTML === '') corrBody.innerHTML = emptyTableRow(6, 'No correlation rules', 'Add one to raise context when related alerts appear together.');
        if (thrBody.innerHTML === '') thrBody.innerHTML = emptyTableRow(6, 'No threshold rules', 'Add one to detect repeated activity inside a time window.');

        files.forEach(function (file) {
            filesBody.innerHTML += '<tr>' +
                '<td class="mono">' + esc(file.key) + '</td>' +
                '<td class="cell-numeric">' + esc(file.ruleCount || 0) + '</td>' +
                '<td class="cell-nowrap">' + formatTime(file.lastModified) + '</td>' +
                '<td><div class="badge-group">' +
                '<button class="btn btn-secondary btn-sm" data-action="edit-postprocessing" data-key="' + escAttr(file.key) + '">Edit</button>' +
                '<button class="btn btn-danger btn-sm" data-action="delete-postprocessing" data-key="' + escAttr(file.key) + '">Delete</button>' +
                '</div></td></tr>';
        });
        if (filesBody.innerHTML === '') filesBody.innerHTML = emptyTableRow(4, 'No postprocessing files', 'Create a JSON file to store correlation or threshold logic.');
    } catch (e) {
        corrBody.innerHTML = emptyTableRow(6, 'Failed to load postprocessing', e.message);
        thrBody.innerHTML = '';
        filesBody.innerHTML = '';
    }
}

// -------------------------------------------------------
// Editor State
// -------------------------------------------------------

function ensurePPEditor() {
    if (ppEditor) return ppEditor;
    ppEditor = RuleCodeEditor.create({
        textareaId: 'pp-editor',
        highlightId: 'pp-highlight',
        gutterId: 'pp-line-numbers',
        canvasId: 'pp-editor-canvas',
        onChange: handlePPEditorChange,
        onSave: savePP,
    });
    return ppEditor;
}

function getPPContent() {
    return ensurePPEditor().getValue();
}

function setPPContent(content) {
    ensurePPEditor().setValue(content || '');
}

function isPPDirty() {
    return getPPContent() !== ppLastSavedContent;
}

function handlePPEditorChange() {
    schedulePPValidation();
    updatePPEditorState();
}

function setPPStatePill(id, state, text) {
    var el = document.getElementById(id);
    if (!el) return;
    el.className = 'state-pill state-' + state;
    el.textContent = text;
}

function schedulePPValidation() {
    clearTimeout(ppValidationTimer);
    ppValidationTimer = setTimeout(function () { validatePP(false); }, 450);
}

function updatePPEditorState() {
    var dirty = isPPDirty();
    var valid = ppValidation && ppValidation.valid;
    var hasValidation = !!ppValidation;
    var validationText = ppIsValidating ? 'Validating' : (valid ? 'Valid' : (hasValidation ? 'Invalid' : 'Not validated'));

    setPPStatePill('pp-dirty-state', dirty ? 'dirty' : 'muted', dirty ? 'Unsaved changes' : 'Clean');
    setPPStatePill('pp-validation-state', ppIsValidating ? 'warning' : (valid ? 'valid' : (hasValidation ? 'error' : 'muted')), validationText);
    setButtonState('save-pp-btn', ppIsSaving || ppIsValidating || !valid || !dirty);
    setHidden('delete-pp-btn', !ppCurrentKey);

    var lastSaved = document.getElementById('pp-last-saved');
    if (lastSaved) lastSaved.textContent = ppLastSavedAt ? 'Last saved ' + formatTime(ppLastSavedAt) : 'Not saved yet';

    var saveStatus = document.getElementById('pp-save-status');
    if (saveStatus) {
        if (ppIsSaving) saveStatus.textContent = 'Saving postprocessing file...';
        else if (!valid) saveStatus.textContent = hasValidation ? 'Fix validation errors before saving.' : 'Validate the JSON before saving.';
        else if (dirty) saveStatus.textContent = 'Valid postprocessing JSON with unsaved changes.';
        else saveStatus.textContent = 'Saved.';
    }
}

function renderPPValidationPanel() {
    var panel = document.getElementById('pp-validation-panel');
    if (!panel) return;

    if (ppIsValidating) {
        panel.innerHTML = '<div class="validation-empty">Validating postprocessing JSON...</div>';
        return;
    }
    if (!ppValidation) {
        panel.innerHTML = '<div class="validation-empty">Validation runs automatically as you type.</div>';
        return;
    }

    var items = [];
    (ppValidation.errors || []).forEach(function (error) {
        items.push('<li class="validation-error"><span>' + esc(error.line ? 'Line ' + error.line : 'Rule') + '</span>' + esc(error.message) + '</li>');
    });
    (ppValidation.warnings || []).forEach(function (warning) {
        items.push('<li class="validation-warning"><span>' + esc(warning.line ? 'Line ' + warning.line : 'Hint') + '</span>' + esc(warning.message) + '</li>');
    });

    if (items.length === 0) {
        panel.innerHTML = '<div class="validation-ok">Postprocessing file is valid and ready to save.</div>';
        return;
    }
    panel.innerHTML = '<ul class="validation-list">' + items.join('') + '</ul>';
}

function renderPPSchemaHints() {
    var panel = document.getElementById('pp-schema-hints');
    if (!panel) return;
    var dynamicHints = ppValidation ? (ppValidation.hints || []) : [];
    var baseHints = [
        'Files can contain one rule object or an array of rules.',
        'Correlation: type, sigmaRuleTitle, lookFor, windowMinutes.',
        'Threshold: type, sigmaRuleTitle, thresholdCount, windowMinutes.',
    ];
    panel.innerHTML = baseHints.concat(dynamicHints).map(function (hint) {
        return '<div class="hint-item">' + esc(hint) + '</div>';
    }).join('');
}

function renderPPMetadata() {
    var list = document.getElementById('pp-metadata');
    if (!list) return;
    var metadata = ppValidation && ppValidation.metadata ? ppValidation.metadata : {};
    var rows = [
        ['File', ppCurrentKey || 'New file'],
        ['Rules', metadata.ruleCount || 0],
        ['Correlation', metadata.correlationCount || 0],
        ['Threshold', metadata.thresholdCount || 0],
    ];
    list.innerHTML = rows.map(function (row) {
        return '<dt>' + esc(row[0]) + '</dt><dd>' + esc(row[1]) + '</dd>';
    }).join('');
}

function renderPPEditorDetails() {
    var markers = [];
    if (ppValidation) {
        (ppValidation.errors || []).forEach(function (error) { if (error.line) markers.push(Object.assign({ severity: 'error' }, error)); });
        (ppValidation.warnings || []).forEach(function (warning) { if (warning.line) markers.push(Object.assign({ severity: 'warning' }, warning)); });
    }
    ensurePPEditor().setMarkers(markers);
    renderPPValidationPanel();
    renderPPSchemaHints();
    renderPPMetadata();
}

async function validatePP(showToast) {
    var requestId = ++ppValidationRequestId;
    ppIsValidating = true;
    updatePPEditorState();
    renderPPValidationPanel();

    try {
        var data = await api('/api/postprocessing/validate', { method: 'POST', body: getPPContent() });
        if (requestId !== ppValidationRequestId) return data;
        ppValidation = data;
        if (showToast) toast(data.valid ? 'Postprocessing JSON is valid' : 'Postprocessing JSON has validation errors', data.valid ? 'success' : 'error');
        return data;
    } catch (e) {
        if (requestId !== ppValidationRequestId) return null;
        ppValidation = { valid: false, errors: [{ message: e.message, line: 1 }], warnings: [], hints: [] };
        if (showToast) toast('Validation failed: ' + e.message, 'error');
        return ppValidation;
    } finally {
        if (requestId === ppValidationRequestId) {
            ppIsValidating = false;
            renderPPEditorDetails();
            updatePPEditorState();
        }
    }
}

// -------------------------------------------------------
// Edit / New / Save / Delete
// -------------------------------------------------------

async function editPPFile(key) {
    ppCurrentKey = key;
    ppLastSavedContent = '';
    ppLastSavedAt = null;
    ppValidation = null;
    document.getElementById('pp-editor-title').textContent = key;
    setHidden('pp-list-view', true);
    setHidden('pp-edit-view', false);
    ensurePPEditor();
    setPPContent('');
    updatePPEditorState();

    try {
        var data = await api('/api/postprocessing/' + encodeURIComponent(key));
        var parsed = JSON.parse(data.content);
        var formatted = JSON.stringify(parsed, null, 2);
        ppLastSavedContent = formatted;
        ppLastSavedAt = data.lastModified || null;
        setPPContent(formatted);
        await validatePP(false);
        ensurePPEditor().focus();
    } catch (e) {
        ppLastSavedContent = '';
        setPPContent('');
        ppValidation = { valid: false, errors: [{ message: 'Failed to load file: ' + e.message, line: 1 }], warnings: [], hints: [] };
        renderPPEditorDetails();
        toast('Failed to load postprocessing file: ' + e.message, 'error');
    }
    updatePPEditorState();
}

function openNewPPEditor(title, template) {
    ppCurrentKey = null;
    ppLastSavedContent = '';
    ppLastSavedAt = null;
    ppValidation = null;
    document.getElementById('pp-editor-title').textContent = title;
    setHidden('pp-list-view', true);
    setHidden('pp-edit-view', false);
    ensurePPEditor();
    setPPContent(JSON.stringify(template, null, 2));
    renderPPEditorDetails();
    validatePP(false);
    ensurePPEditor().focus();
    updatePPEditorState();
}

function newPostprocessingRule(type) {
    openNewPPEditor('New ' + type + ' rule', ppTemplates[type] || ppTemplates.correlation);
}

function newPostprocessingFile() {
    openNewPPEditor('New postprocessing file', ppTemplates.correlation);
}

async function savePP() {
    if (ppIsSaving) return;
    var validation = await validatePP(false);
    if (!validation || !validation.valid) {
        toast('Fix validation errors before saving', 'error');
        return;
    }

    var parsed;
    try {
        parsed = JSON.parse(getPPContent());
    } catch (e) {
        toast('Invalid JSON: ' + e.message, 'error');
        return;
    }
    var rules = Array.isArray(parsed) ? parsed : [parsed];
    var content = JSON.stringify(rules, null, 2);

    var key = ppCurrentKey;
    if (!key) {
        key = await showDialog('Save File', 'Enter a filename for this postprocessing file:', { input: true, placeholder: 'my_rule.json', confirmText: 'Save' });
        if (!key) return;
        if (!key.endsWith('.json')) key += '.json';
    }

    ppIsSaving = true;
    updatePPEditorState();
    try {
        var response = await api('/api/postprocessing/' + encodeURIComponent(key), { method: 'PUT', body: content });
        ppCurrentKey = response.key || key;
        ppLastSavedContent = content;
        ppLastSavedAt = new Date().toISOString();
        document.getElementById('pp-editor-title').textContent = ppCurrentKey;
        setPPContent(content);
        await validatePP(false);
        toast('Postprocessing file saved');
    } catch (e) {
        toast('Save failed: ' + e.message, 'error');
    } finally {
        ppIsSaving = false;
        updatePPEditorState();
    }
}

async function deletePPFile(key) {
    var ok = await showDialog('Delete File', 'Delete ' + key + '? This cannot be undone.', { confirmText: 'Delete', danger: true });
    if (!ok) return;
    try {
        await api('/api/postprocessing/' + encodeURIComponent(key), { method: 'DELETE' });
        toast('File deleted');
        loadPostprocessing();
    } catch (e) {
        toast('Delete failed: ' + e.message, 'error');
    }
}

async function deleteCurrentPP() {
    if (!ppCurrentKey) return;
    await deletePPFile(ppCurrentKey);
}

async function backToPPList() {
    if (isPPDirty()) {
        var ok = await showDialog('Unsaved Changes', 'Return to the postprocessing list without saving your editor changes?', { confirmText: 'Discard changes' });
        if (!ok) return;
    }
    loadPostprocessing();
}
