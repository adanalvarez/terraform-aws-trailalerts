/**
 * exceptions.js — Exception rules CRUD.
 *
 * Globals defined here:
 *   loadExceptions(), renderExceptionsTable(),
 *   editException(), editAllExceptions(), newException(),
 *   removeException(), saveExceptions(), backToExcList()
 *
 * Depends on: api() (api.js), toast() / showDialog() / esc() / escAttr() (ui.js)
 */
'use strict';

var exceptionsCache = {};

// -------------------------------------------------------
// Load & Render
// -------------------------------------------------------

async function loadExceptions() {
    var tbody = document.getElementById('exceptions-body');
    tbody.innerHTML = '<tr><td colspan="5"><div class="loading"><div class="spinner"></div></div></td></tr>';

    try {
        var data = await api('/api/exceptions');
        exceptionsCache = data.exceptions || {};
        renderExceptionsTable();
    } catch (e) {
        tbody.innerHTML = '<tr><td colspan="5" style="color:var(--critical);">Error: ' + esc(e.message) + '</td></tr>';
    }
}

function renderExceptionsTable() {
    var tbody = document.getElementById('exceptions-body');
    tbody.innerHTML = '';
    var keys = Object.keys(exceptionsCache);
    if (keys.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-muted);">No exception rules configured</td></tr>';
        return;
    }
    keys.sort().forEach(function (rule) {
        var exc   = exceptionsCache[rule] || {};
        var actors = (exc.excludedActors || []).length;
        var ips    = (exc.excludedSourceIPs || []).length;
        var regex  = (exc.excludedActorsRegex || []).length;
        tbody.innerHTML += '<tr>' +
            '<td>' + esc(rule) + '</td>' +
            '<td>' + esc(actors) + '</td>' +
            '<td>' + esc(ips) + '</td>' +
            '<td>' + esc(regex) + '</td>' +
            '<td style="display:flex; gap:0.5rem;">' +
            '<button class="btn btn-secondary btn-sm" onclick="editException(\'' + escAttr(rule) + '\')">Edit</button>' +
            '<button class="btn btn-danger btn-sm" onclick="removeException(\'' + escAttr(rule) + '\')">Remove</button>' +
            '</td></tr>';
    });
}

// -------------------------------------------------------
// Edit / New / Save / Remove
// -------------------------------------------------------

function editException(rule) {
    document.getElementById('exc-editor-title').textContent = rule ? ('Exception: ' + rule) : 'Exceptions (JSON)';
    document.getElementById('exc-list-view').style.display = 'none';
    document.getElementById('exc-edit-view').style.display = '';

    if (rule && exceptionsCache[rule]) {
        document.getElementById('exc-editor').value = JSON.stringify({ [rule]: exceptionsCache[rule] }, null, 2);
    } else {
        document.getElementById('exc-editor').value = JSON.stringify(exceptionsCache, null, 2);
    }
}

function editAllExceptions() {
    document.getElementById('exc-editor-title').textContent = 'All Exceptions (JSON)';
    document.getElementById('exc-list-view').style.display = 'none';
    document.getElementById('exc-edit-view').style.display = '';
    document.getElementById('exc-editor').value = JSON.stringify(exceptionsCache, null, 2);
}

async function newException() {
    var rule = await showDialog('New Exception', 'Enter the Sigma rule title to add exceptions for:', { input: true, placeholder: 'Rule title', confirmText: 'Add' });
    if (!rule) return;
    if (exceptionsCache[rule]) {
        editException(rule);
        return;
    }
    exceptionsCache[rule] = { excludedActors: [], excludedSourceIPs: [], excludedActorsRegex: [] };
    editException(rule);
}

async function removeException(rule) {
    var ok = await showDialog('Remove Exception', 'Remove all exceptions for "' + rule + '"?', { confirmText: 'Remove', danger: true });
    if (!ok) return;
    delete exceptionsCache[rule];
    try {
        await api('/api/exceptions', { method: 'PUT', body: JSON.stringify(exceptionsCache) });
        renderExceptionsTable();
    } catch (e) {
        toast('Failed to save: ' + e.message, 'error');
        loadExceptions();
    }
}

async function saveExceptions() {
    var editor = document.getElementById('exc-editor');
    var parsed;
    try { parsed = JSON.parse(editor.value); } catch (e) {
        toast('Invalid JSON: ' + e.message, 'error');
        return;
    }
    // Merge the edited fragment into the full cache
    Object.assign(exceptionsCache, parsed);

    try {
        await api('/api/exceptions', { method: 'PUT', body: JSON.stringify(exceptionsCache) });
        toast('Exceptions saved');
        backToExcList();
    } catch (e) {
        toast('Save failed: ' + e.message, 'error');
    }
}

function backToExcList() {
    document.getElementById('exc-list-view').style.display = '';
    document.getElementById('exc-edit-view').style.display = 'none';
    loadExceptions();
}
