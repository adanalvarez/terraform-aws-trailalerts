/**
 * exceptions.js - Exception rules CRUD with workflow-aware JSON editor.
 *
 * Globals defined here:
 *   loadExceptions(), renderExceptionsTable(), editException(),
 *   editAllExceptions(), newException(), validateExceptions(),
 *   removeException(), deleteCurrentException(), saveExceptions(),
 *   backToExcList()
 *
 * Depends on: api() (api.js), RuleCodeEditor (rule_editor.js), and UI helpers.
 */
'use strict';

var exceptionsCache = {};
var exceptionsLastModified = null;
var excCurrentRule = null;
var excEditMode = 'all';
var excLastSavedContent = '';
var excLastSavedAt = null;
var excEditor = null;
var excValidation = null;
var excValidationTimer = null;
var excValidationRequestId = 0;
var excIsValidating = false;
var excIsSaving = false;

// -------------------------------------------------------
// Load & Render
// -------------------------------------------------------

async function loadExceptions() {
    setHidden('exc-list-view', false);
    setHidden('exc-edit-view', true);

    var tbody = document.getElementById('exceptions-body');
    tbody.innerHTML = '<tr><td colspan="5"><div class="loading"><div class="spinner"></div></div></td></tr>';

    try {
        var data = await api('/api/exceptions');
        exceptionsCache = data.exceptions || {};
        exceptionsLastModified = data.lastModified || null;
        renderExceptionsTable();
    } catch (error) {
        tbody.innerHTML = emptyTableRow(5, 'Failed to load exceptions', error.message);
    }
}

function renderExceptionsTable() {
    var tbody = document.getElementById('exceptions-body');
    tbody.innerHTML = '';
    var keys = Object.keys(exceptionsCache);
    if (keys.length === 0) {
        tbody.innerHTML = emptyTableRow(5, 'No exception rules configured', 'Add a rule exception to reduce known benign alert noise.');
        return;
    }
    keys.sort().forEach(function (rule) {
        var exceptionConfig = exceptionsCache[rule] || {};
        var actors = (exceptionConfig.excludedActors || []).length;
        var ips = (exceptionConfig.excludedSourceIPs || []).length;
        var regex = (exceptionConfig.excludedActorsRegex || []).length;
        tbody.innerHTML += '<tr>' +
            '<td><div class="cell-primary">' + esc(rule) + '</div></td>' +
            '<td class="cell-numeric">' + esc(actors) + '</td>' +
            '<td class="cell-numeric">' + esc(ips) + '</td>' +
            '<td class="cell-numeric">' + esc(regex) + '</td>' +
            '<td><div class="badge-group">' +
            '<button class="btn btn-secondary btn-sm" data-action="edit-exception" data-rule="' + escAttr(rule) + '">Edit</button>' +
            '<button class="btn btn-danger btn-sm" data-action="remove-exception" data-rule="' + escAttr(rule) + '">Remove</button></div>' +
            '</td></tr>';
    });
}

// -------------------------------------------------------
// Editor State
// -------------------------------------------------------

function ensureExceptionEditor() {
    if (excEditor) return excEditor;
    excEditor = RuleCodeEditor.create({
        textareaId: 'exc-editor',
        highlightId: 'exc-highlight',
        gutterId: 'exc-line-numbers',
        canvasId: 'exc-editor-canvas',
        onChange: handleExceptionEditorChange,
        onSave: saveExceptions,
    });
    return excEditor;
}

function getExceptionContent() {
    return ensureExceptionEditor().getValue();
}

function setExceptionContent(content) {
    ensureExceptionEditor().setValue(content || '');
}

function isExceptionDirty() {
    return getExceptionContent() !== excLastSavedContent;
}

function handleExceptionEditorChange() {
    scheduleExceptionValidation();
    updateExceptionEditorState();
}

function setExceptionStatePill(id, state, text) {
    var el = document.getElementById(id);
    if (!el) return;
    el.className = 'state-pill state-' + state;
    el.textContent = text;
}

function scheduleExceptionValidation() {
    clearTimeout(excValidationTimer);
    excValidationTimer = setTimeout(function () { validateExceptions(false); }, 450);
}

function updateExceptionEditorState() {
    var dirty = isExceptionDirty();
    var valid = excValidation && excValidation.valid;
    var hasValidation = !!excValidation;
    var validationText = excIsValidating ? 'Validating' : (valid ? 'Valid' : (hasValidation ? 'Invalid' : 'Not validated'));

    setExceptionStatePill('exc-dirty-state', dirty ? 'dirty' : 'muted', dirty ? 'Unsaved changes' : 'Clean');
    setExceptionStatePill('exc-validation-state', excIsValidating ? 'warning' : (valid ? 'valid' : (hasValidation ? 'error' : 'muted')), validationText);
    setButtonState('save-exceptions-btn', excIsSaving || excIsValidating || !valid || !dirty);
    setHidden('delete-current-exception-btn', !excCurrentRule);

    var lastSaved = document.getElementById('exc-last-saved');
    if (lastSaved) lastSaved.textContent = excLastSavedAt ? 'Last saved ' + formatTime(excLastSavedAt) : 'Not saved yet';

    var saveStatus = document.getElementById('exc-save-status');
    if (saveStatus) {
        if (excIsSaving) saveStatus.textContent = 'Saving exceptions...';
        else if (!valid) saveStatus.textContent = hasValidation ? 'Fix validation errors before saving.' : 'Validate the JSON before saving.';
        else if (dirty) saveStatus.textContent = 'Valid exceptions JSON with unsaved changes.';
        else saveStatus.textContent = 'Saved.';
    }
}

function renderExceptionValidationPanel() {
    var panel = document.getElementById('exc-validation-panel');
    if (!panel) return;

    if (excIsValidating) {
        panel.innerHTML = '<div class="validation-empty">Validating exceptions JSON...</div>';
        return;
    }
    if (!excValidation) {
        panel.innerHTML = '<div class="validation-empty">Validation runs automatically as you type.</div>';
        return;
    }

    var items = [];
    (excValidation.errors || []).forEach(function (error) {
        items.push('<li class="validation-error"><span>' + esc(error.line ? 'Line ' + error.line : 'Rule') + '</span>' + esc(error.message) + '</li>');
    });
    (excValidation.warnings || []).forEach(function (warning) {
        items.push('<li class="validation-warning"><span>' + esc(warning.line ? 'Line ' + warning.line : 'Hint') + '</span>' + esc(warning.message) + '</li>');
    });

    if (items.length === 0) {
        panel.innerHTML = '<div class="validation-ok">Exceptions JSON is valid and ready to save.</div>';
        return;
    }
    panel.innerHTML = '<ul class="validation-list">' + items.join('') + '</ul>';
}

function renderExceptionSchemaHints() {
    var panel = document.getElementById('exc-schema-hints');
    if (!panel) return;
    var dynamicHints = excValidation ? (excValidation.hints || []) : [];
    var baseHints = [
        'Top-level keys must match Sigma rule titles exactly.',
        'excludedActors and excludedSourceIPs use exact string matches.',
        'excludedActorsRegex uses Python regular expressions matched against the actor.',
    ];
    panel.innerHTML = baseHints.concat(dynamicHints).map(function (hint) {
        return '<div class="hint-item">' + esc(hint) + '</div>';
    }).join('');
}

function renderExceptionMetadata() {
    var list = document.getElementById('exc-metadata');
    if (!list) return;
    var metadata = excValidation && excValidation.metadata ? excValidation.metadata : {};
    var rows = [
        ['Scope', excCurrentRule || 'All exceptions'],
        ['Rules', metadata.ruleCount || 0],
        ['Actors', metadata.actorCount || 0],
        ['Source IPs', metadata.sourceIpCount || 0],
        ['Regex', metadata.regexCount || 0],
    ];
    list.innerHTML = rows.map(function (row) {
        return '<dt>' + esc(row[0]) + '</dt><dd>' + esc(row[1]) + '</dd>';
    }).join('');
}

function renderExceptionEditorDetails() {
    var markers = [];
    if (excValidation) {
        (excValidation.errors || []).forEach(function (error) { if (error.line) markers.push(Object.assign({ severity: 'error' }, error)); });
        (excValidation.warnings || []).forEach(function (warning) { if (warning.line) markers.push(Object.assign({ severity: 'warning' }, warning)); });
    }
    ensureExceptionEditor().setMarkers(markers);
    renderExceptionValidationPanel();
    renderExceptionSchemaHints();
    renderExceptionMetadata();
}

async function validateExceptions(showToast) {
    var requestId = ++excValidationRequestId;
    excIsValidating = true;
    updateExceptionEditorState();
    renderExceptionValidationPanel();

    try {
        var data = await api('/api/exceptions/validate', { method: 'POST', body: getExceptionContent() });
        if (requestId !== excValidationRequestId) return data;
        excValidation = data;
        if (showToast) toast(data.valid ? 'Exceptions JSON is valid' : 'Exceptions JSON has validation errors', data.valid ? 'success' : 'error');
        return data;
    } catch (error) {
        if (requestId !== excValidationRequestId) return null;
        excValidation = { valid: false, errors: [{ message: error.message, line: 1 }], warnings: [], hints: [] };
        if (showToast) toast('Validation failed: ' + error.message, 'error');
        return excValidation;
    } finally {
        if (requestId === excValidationRequestId) {
            excIsValidating = false;
            renderExceptionEditorDetails();
            updateExceptionEditorState();
        }
    }
}

// -------------------------------------------------------
// Edit / New / Save / Remove
// -------------------------------------------------------

function openExceptionEditor(title, content, currentRule, mode, lastSavedAt) {
    excCurrentRule = currentRule || null;
    excEditMode = mode || 'all';
    excLastSavedAt = lastSavedAt || null;
    excValidation = null;
    document.getElementById('exc-editor-title').textContent = title;
    setHidden('exc-list-view', true);
    setHidden('exc-edit-view', false);
    ensureExceptionEditor();
    excLastSavedContent = lastSavedAt ? (content || '') : '';
    setExceptionContent(content || '');
    renderExceptionEditorDetails();
    validateExceptions(false);
    ensureExceptionEditor().focus();
    updateExceptionEditorState();
}

function editException(rule) {
    var exceptionConfig = exceptionsCache[rule] || { excludedActors: [], excludedSourceIPs: [], excludedActorsRegex: [] };
    var content = JSON.stringify(Object.assign({}, { [rule]: exceptionConfig }), null, 2);
    openExceptionEditor('Exception: ' + rule, content, rule, 'single', exceptionsLastModified);
}

function editAllExceptions() {
    var content = JSON.stringify(exceptionsCache, null, 2);
    openExceptionEditor('All Exceptions (JSON)', content, null, 'all', exceptionsLastModified);
}

async function newException() {
    var rule = await showDialog('New Exception', 'Enter the Sigma rule title to add exceptions for:', { input: true, placeholder: 'Rule title', confirmText: 'Add' });
    if (!rule) return;
    if (exceptionsCache[rule]) {
        editException(rule);
        return;
    }
    var template = {};
    template[rule] = { excludedActors: [], excludedSourceIPs: [], excludedActorsRegex: [] };
    openExceptionEditor('New exception: ' + rule, JSON.stringify(template, null, 2), rule, 'single', null);
}

async function persistExceptions(nextCache) {
    await api('/api/exceptions', { method: 'PUT', body: JSON.stringify(nextCache, null, 2) });
    exceptionsCache = nextCache;
    exceptionsLastModified = new Date().toISOString();
}

async function removeException(rule) {
    var ok = await showDialog('Remove Exception', 'Remove all exceptions for "' + rule + '"?', { confirmText: 'Remove', danger: true });
    if (!ok) return;
    var nextCache = Object.assign({}, exceptionsCache);
    delete nextCache[rule];
    try {
        await persistExceptions(nextCache);
        renderExceptionsTable();
        toast('Exception removed');
    } catch (error) {
        toast('Failed to save: ' + error.message, 'error');
        loadExceptions();
    }
}

async function deleteCurrentException() {
    if (!excCurrentRule) return;
    var ok = await showDialog('Delete Exception', 'Delete the exception for "' + excCurrentRule + '"? This cannot be undone.', { confirmText: 'Delete', danger: true });
    if (!ok) return;
    var nextCache = Object.assign({}, exceptionsCache);
    delete nextCache[excCurrentRule];
    try {
        await persistExceptions(nextCache);
        toast('Exception deleted');
        loadExceptions();
    } catch (error) {
        toast('Delete failed: ' + error.message, 'error');
    }
}

async function saveExceptions() {
    if (excIsSaving) return;
    var validation = await validateExceptions(false);
    if (!validation || !validation.valid) {
        toast('Fix validation errors before saving', 'error');
        return;
    }

    var parsed;
    try {
        parsed = JSON.parse(getExceptionContent());
    } catch (error) {
        toast('Invalid JSON: ' + error.message, 'error');
        return;
    }

    var nextCache = excEditMode === 'all' ? parsed : Object.assign({}, exceptionsCache);
    if (excEditMode !== 'all') {
        if (excCurrentRule && !Object.prototype.hasOwnProperty.call(parsed, excCurrentRule)) {
            delete nextCache[excCurrentRule];
        }
        Object.assign(nextCache, parsed);
    }

    excIsSaving = true;
    updateExceptionEditorState();
    try {
        await persistExceptions(nextCache);
        var formatted = excEditMode === 'all' ? JSON.stringify(exceptionsCache, null, 2) : JSON.stringify(parsed, null, 2);
        var editedKeys = Object.keys(parsed);
        if (excEditMode !== 'all' && editedKeys.length === 1) {
            excCurrentRule = editedKeys[0];
            document.getElementById('exc-editor-title').textContent = 'Exception: ' + excCurrentRule;
        }
        excLastSavedContent = formatted;
        excLastSavedAt = exceptionsLastModified;
        setExceptionContent(formatted);
        await validateExceptions(false);
        toast('Exceptions saved');
    } catch (error) {
        toast('Save failed: ' + error.message, 'error');
    } finally {
        excIsSaving = false;
        updateExceptionEditorState();
    }
}

async function backToExcList() {
    if (isExceptionDirty()) {
        var ok = await showDialog('Unsaved Changes', 'Return to the exceptions list without saving your editor changes?', { confirmText: 'Discard changes' });
        if (!ok) return;
    }
    loadExceptions();
}
