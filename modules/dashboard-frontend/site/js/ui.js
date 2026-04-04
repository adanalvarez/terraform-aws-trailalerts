/**
 * ui.js — Shared UI utilities: toast, dialog, escaping, formatting, debounce.
 *
 * Globals defined here:
 *   toast(), showDialog(), esc(), escAttr(), formatTime(),
 *   debouncedRenderRules(), debouncedRenderAlerts()
 */
'use strict';

// -------------------------------------------------------
// Toast Notifications
// -------------------------------------------------------

/**
 * Show a brief non-blocking notification.
 * @param {string} msg  - Message text.
 * @param {'success'|'error'} [type='success']
 */
function toast(msg, type) {
    type = type || 'success';
    var container = document.getElementById('toast-container');
    var el = document.createElement('div');
    el.className = 'toast toast-' + type;
    el.textContent = msg;
    container.appendChild(el);
    setTimeout(function () { el.remove(); }, 4000);
}

// -------------------------------------------------------
// Branded Dialog (replaces alert / prompt / confirm)
// -------------------------------------------------------

/**
 * Show a branded modal dialog.
 *
 * @param {string} title
 * @param {string} message
 * @param {Object} [opts]
 * @param {boolean}  [opts.input]        — show a text input
 * @param {string}   [opts.defaultValue] — pre-fill the input
 * @param {string}   [opts.placeholder]  — input placeholder
 * @param {string}   [opts.confirmText]  — confirm-button label (default "Confirm")
 * @param {boolean}  [opts.danger]       — red confirm button
 * @returns {Promise<string|boolean|null>}  input value, true, or null (cancelled)
 */
function showDialog(title, message, opts) {
    opts = opts || {};
    return new Promise(function (resolve) {
        var overlay   = document.getElementById('dialog-modal');
        var inputEl   = document.getElementById('dialog-input');
        var confirmBtn = document.getElementById('dialog-confirm');
        var cancelBtn  = document.getElementById('dialog-cancel');

        document.getElementById('dialog-title').textContent = title;
        document.getElementById('dialog-message').textContent = message;
        confirmBtn.textContent = opts.confirmText || 'Confirm';
        confirmBtn.className = opts.danger ? 'btn btn-danger btn-sm' : 'btn btn-primary btn-sm';

        if (opts.input) {
            inputEl.style.display = '';
            inputEl.value = opts.defaultValue || '';
            inputEl.placeholder = opts.placeholder || '';
        } else {
            inputEl.style.display = 'none';
        }

        overlay.classList.add('active');
        if (opts.input) setTimeout(function () { inputEl.focus(); }, 50);

        var ac = new AbortController();
        function close(val) { ac.abort(); overlay.classList.remove('active'); resolve(val); }

        confirmBtn.addEventListener('click', function () { close(opts.input ? inputEl.value : true); }, { signal: ac.signal });
        cancelBtn.addEventListener('click', function () { close(null); }, { signal: ac.signal });
        overlay.addEventListener('click', function (e) { if (e.target === overlay) close(null); }, { signal: ac.signal });
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') close(null);
            if (e.key === 'Enter' && opts.input) close(inputEl.value);
        }, { signal: ac.signal });
    });
}

// -------------------------------------------------------
// Escaping
// -------------------------------------------------------

/** Escape a value for safe insertion into innerHTML. */
function esc(str) {
    var div = document.createElement('div');
    div.textContent = String(str || '');
    return div.innerHTML;
}

/**
 * Escape a value for safe use inside onclick="fn('VALUE')" attributes.
 * Order matters: backslash first (JS context), then single-quote, then HTML entities.
 */
function escAttr(str) {
    return String(str || '')
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "\\'")
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

// -------------------------------------------------------
// Formatting
// -------------------------------------------------------

/** Format an ISO timestamp to a compact locale string. */
function formatTime(ts) {
    if (!ts) return '';
    try {
        var d = new Date(ts);
        return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) + ' ' +
               d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', hour12: false });
    } catch (_) { return ts; }
}

// -------------------------------------------------------
// Debounce Helpers (for search inputs)
// -------------------------------------------------------

var _rulesSearchTimer, _alertsSearchTimer;

function debouncedRenderRules() {
    clearTimeout(_rulesSearchTimer);
    _rulesSearchTimer = setTimeout(renderRulesTable, 200);
}

function debouncedRenderAlerts() {
    clearTimeout(_alertsSearchTimer);
    _alertsSearchTimer = setTimeout(renderAlertsTable, 200);
}
