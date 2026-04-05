/**
 * postprocessing.js — Postprocessing rules CRUD (correlation & threshold).
 *
 * Globals defined here:
 *   loadPostprocessing(), editPPFile(), newPostprocessingRule(),
 *   newPostprocessingFile(), savePP(), deletePPFile(),
 *   deleteCurrentPP(), backToPPList()
 *
 * Depends on: api() (api.js), toast() / showDialog() / esc() / escAttr() / formatTime() (ui.js)
 */
'use strict';

var ppCurrentKey = null;

// -------------------------------------------------------
// Load & Render
// -------------------------------------------------------

async function loadPostprocessing() {
    var corrBody  = document.getElementById('correlation-body');
    var thrBody   = document.getElementById('threshold-body');
    var filesBody = document.getElementById('pp-files-body');
    corrBody.innerHTML = thrBody.innerHTML = filesBody.innerHTML =
        '<tr><td colspan="6"><div class="loading"><div class="spinner"></div></div></td></tr>';

    try {
        var data             = await api('/api/postprocessing');
        var correlationRules = data.correlationRules || [];
        var thresholdRules   = data.thresholdRules || [];
        var files            = data.files || [];

        corrBody.innerHTML  = '';
        thrBody.innerHTML   = '';
        filesBody.innerHTML = '';

        correlationRules.forEach(function (rule) {
            var lookFor  = Array.isArray(rule.lookFor) ? rule.lookFor : (rule.lookFor ? [rule.lookFor] : []);
            var severity = rule.adjustSeverity || rule.severity_adjustment || '-';
            corrBody.innerHTML += '<tr>' +
                '<td>' + esc(rule.sigmaRuleTitle || '') + '</td>' +
                '<td>' + esc(lookFor.join(', ')) + '</td>' +
                '<td>' + esc(rule.windowMinutes || '') + '</td>' +
                '<td>' + esc(severity) + '</td>' +
                '<td>' + esc(rule._file || '') + '</td>' +
                '<td><button class="btn btn-secondary btn-sm" onclick="editPPFile(\'' + escAttr(rule._file || '') + '\')">Edit</button></td>' +
                '</tr>';
        });

        thresholdRules.forEach(function (rule) {
            var severity = rule.adjustSeverity || rule.severity_adjustment || '-';
            thrBody.innerHTML += '<tr>' +
                '<td>' + esc(rule.sigmaRuleTitle || '') + '</td>' +
                '<td>' + esc(rule.thresholdCount || '') + '</td>' +
                '<td>' + esc(rule.windowMinutes || '') + '</td>' +
                '<td>' + esc(severity) + '</td>' +
                '<td>' + esc(rule._file || '') + '</td>' +
                '<td><button class="btn btn-secondary btn-sm" onclick="editPPFile(\'' + escAttr(rule._file || '') + '\')">Edit</button></td>' +
                '</tr>';
        });

        if (corrBody.innerHTML === '') corrBody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted);">No correlation rules</td></tr>';
        if (thrBody.innerHTML === '') thrBody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted);">No threshold rules</td></tr>';

        files.forEach(function (f) {
            filesBody.innerHTML += '<tr>' +
                '<td>' + esc(f.key) + '</td>' +
                '<td>' + esc(f.ruleCount || 0) + '</td>' +
                '<td>' + formatTime(f.lastModified) + '</td>' +
                '<td style="display:flex; gap:0.5rem;">' +
                '<button class="btn btn-secondary btn-sm" onclick="editPPFile(\'' + escAttr(f.key) + '\')">Edit</button>' +
                '<button class="btn btn-danger btn-sm" onclick="deletePPFile(\'' + escAttr(f.key) + '\')">Delete</button>' +
                '</td></tr>';
        });
        if (filesBody.innerHTML === '') filesBody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:var(--text-muted);">No files</td></tr>';
    } catch (e) {
        corrBody.innerHTML  = '<tr><td colspan="6" style="color:var(--critical);">Error: ' + esc(e.message) + '</td></tr>';
        thrBody.innerHTML   = '';
        filesBody.innerHTML = '';
    }
}

// -------------------------------------------------------
// Edit / New / Save / Delete
// -------------------------------------------------------

async function editPPFile(key) {
    ppCurrentKey = key;
    document.getElementById('pp-editor-title').textContent = key;
    document.getElementById('delete-pp-btn').style.display = '';
    document.getElementById('pp-editor').value = 'Loading...';
    document.getElementById('pp-list-view').style.display = 'none';
    document.getElementById('pp-edit-view').style.display = '';

    try {
        var data   = await api('/api/postprocessing/' + encodeURIComponent(key));
        var parsed = JSON.parse(data.content);
        document.getElementById('pp-editor').value = JSON.stringify(parsed, null, 2);
    } catch (e) {
        document.getElementById('pp-editor').value = '// Error loading: ' + e.message;
    }
}

function newPostprocessingRule(type) {
    ppCurrentKey = null;
    document.getElementById('pp-editor-title').textContent = 'New ' + type + ' rule';
    document.getElementById('delete-pp-btn').style.display = 'none';
    document.getElementById('pp-list-view').style.display = 'none';
    document.getElementById('pp-edit-view').style.display = '';

    var template = type === 'correlation'
        ? { type: 'correlation', sigmaRuleTitle: '', lookFor: ['field1', 'field2'], windowMinutes: 10, adjustSeverity: 'high' }
        : { type: 'threshold', sigmaRuleTitle: '', thresholdCount: 5, windowMinutes: 10, adjustSeverity: 'critical' };
    document.getElementById('pp-editor').value = JSON.stringify(template, null, 2);
}

function newPostprocessingFile() {
    ppCurrentKey = null;
    document.getElementById('pp-editor-title').textContent = 'New postprocessing file';
    document.getElementById('delete-pp-btn').style.display = 'none';
    document.getElementById('pp-list-view').style.display = 'none';
    document.getElementById('pp-edit-view').style.display = '';

    var template = { type: 'correlation', sigmaRuleTitle: 'ExampleRule', lookFor: ['field1'], windowMinutes: 10, adjustSeverity: 'high' };
    document.getElementById('pp-editor').value = JSON.stringify(template, null, 2);
}

async function savePP() {
    var editor = document.getElementById('pp-editor');
    var content;
    try { content = JSON.parse(editor.value); } catch (e) {
        toast('Invalid JSON: ' + e.message, 'error');
        return;
    }

    // Lambda expects a JSON array of rules
    if (!Array.isArray(content)) content = [content];

    var key = ppCurrentKey;
    if (!key) {
        key = await showDialog('Save File', 'Enter a filename for this postprocessing file:', { input: true, placeholder: 'my_rule.json', confirmText: 'Save' });
        if (!key) return;
        if (!key.endsWith('.json')) key += '.json';
    }

    try {
        await api('/api/postprocessing/' + encodeURIComponent(key), { method: 'PUT', body: JSON.stringify(content) });
        ppCurrentKey = key;
        document.getElementById('pp-editor-title').textContent = key;
        document.getElementById('delete-pp-btn').style.display = '';
        toast('Postprocessing file saved');
        backToPPList();
    } catch (e) {
        toast('Save failed: ' + e.message, 'error');
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
    backToPPList();
}

function backToPPList() {
    document.getElementById('pp-list-view').style.display = '';
    document.getElementById('pp-edit-view').style.display = 'none';
    loadPostprocessing();
}
