/**
 * app.js — Navigation and application bootstrap.
 *
 * Loaded last. Wires up page switching and runs the initial auth check.
 *
 * Depends on:
 *   isAuthenticated(), getUserEmail() (auth.js),
 *   loadOverview/loadRules/loadAlerts/loadPostprocessing/loadExceptions (page modules)
 */
'use strict';

// -------------------------------------------------------
// Navigation
// -------------------------------------------------------

function showPage(page) {
    document.querySelectorAll('.page').forEach(function (p) { p.classList.remove('active'); });
    document.querySelectorAll('.nav-btn').forEach(function (b) { b.classList.remove('active'); });
    document.getElementById('page-' + page).classList.add('active');
    document.querySelector('[data-page="' + page + '"]').classList.add('active');

    if (page === 'overview')       loadOverview();
    if (page === 'rules')          loadRules();
    if (page === 'alerts')         loadAlerts();
    if (page === 'postprocessing') loadPostprocessing();
    if (page === 'exceptions')     loadExceptions();
}

// -------------------------------------------------------
// Init
// -------------------------------------------------------

(function init() {
    if (isAuthenticated()) {
        document.getElementById('login-screen').style.display = 'none';
        document.getElementById('app').style.display = '';
        document.getElementById('user-email').textContent = getUserEmail();
        loadOverview();
    }
})();
