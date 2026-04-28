/**
 * app.js - Navigation, static event wiring, and application bootstrap.
 */
'use strict';

function showPage(page) {
    var pageLabels = {
        overview: 'overview',
        rules: 'rules',
        postprocessing: 'postprocessing',
        exceptions: 'exceptions',
        alerts: 'alerts',
    };

    document.querySelectorAll('.page').forEach(function (p) { p.classList.remove('active'); });
    document.querySelectorAll('.nav-btn').forEach(function (button) {
        button.classList.remove('active');
        button.removeAttribute('aria-current');
    });

    var pageEl = document.getElementById('page-' + page);
    if (pageEl) pageEl.classList.add('active');

    var pageName = document.getElementById('header-page-name');
    if (pageName) pageName.textContent = pageLabels[page] || page;

    document.querySelectorAll('.nav-btn').forEach(function (button) {
        if (button.dataset.page === page) {
            button.classList.add('active');
            button.setAttribute('aria-current', 'page');
        }
    });

    if (page === 'overview') loadOverview();
    if (page === 'rules') loadRules();
    if (page === 'alerts') loadAlerts();
    if (page === 'postprocessing') loadPostprocessing();
    if (page === 'exceptions') loadExceptions();
}

function handleAction(actionEl) {
    var action = actionEl.dataset.action;
    if (!action) return;

    if (action === 'toggle-password') togglePasswordVisibility(actionEl);
    if (action === 'forgot-password') showForgotPassword();
    if (action === 'show-login') showLoginStep(actionEl.dataset.step || 'credentials');
    if (action === 'logout') logout();

    if (action === 'overview-alert-filter') openOverviewAlertFilter(actionEl.dataset.severity || '');

    if (action === 'new-rule') newRule();
    if (action === 'sort-rules') sortRules(actionEl, actionEl.dataset.sort);
    if (action === 'edit-rule') editRule(actionEl.dataset.key, actionEl.dataset.enabled !== 'false');
    if (action === 'clone-rule') cloneRule(actionEl.dataset.key, actionEl.dataset.enabled !== 'false');
    if (action === 'back-rules-list') backToRulesList();
    if (action === 'validate-rule') validateCurrentRule(true);
    if (action === 'test-rule') testCurrentRule();
    if (action === 'load-rule-version') loadRuleVersion(actionEl.dataset.versionId);
    if (action === 'toggle-rule-state') toggleRuleState(actionEl.dataset.key, actionEl.dataset.enabled !== 'false');
    if (action === 'toggle-current-rule-state') toggleCurrentRuleState();
    if (action === 'clone-current-rule') cloneCurrentRule();
    if (action === 'bulk-enable-rules') bulkSetRuleState(true);
    if (action === 'bulk-disable-rules') bulkSetRuleState(false);
    if (action === 'bulk-delete-rules') bulkDeleteRules();
    if (action === 'delete-current-rule') deleteCurrentRule();
    if (action === 'save-rule') saveRule();

    if (action === 'load-alerts') loadAlerts();
    if (action === 'load-more-alerts') loadMoreAlerts();
    if (action === 'filter-alert-severity') setAlertSeverityFilter(actionEl.dataset.severity || '');
    if (action === 'sort-alerts') sortAlerts(actionEl, actionEl.dataset.sort);
    if (action === 'view-alert') viewAlertDetail(actionEl.dataset.pk, actionEl.dataset.sk);
    if (action === 'close-modal') closeModal();

    if (action === 'new-postprocessing-rule') newPostprocessingRule(actionEl.dataset.type);
    if (action === 'new-postprocessing-file') newPostprocessingFile();
    if (action === 'edit-postprocessing') editPPFile(actionEl.dataset.key);
    if (action === 'delete-postprocessing') deletePPFile(actionEl.dataset.key);
    if (action === 'back-pp-list') backToPPList();
    if (action === 'validate-pp') validatePP(true);
    if (action === 'delete-current-pp') deleteCurrentPP();
    if (action === 'save-pp') savePP();

    if (action === 'new-exception') newException();
    if (action === 'edit-exception') editException(actionEl.dataset.rule);
    if (action === 'edit-all-exceptions') editAllExceptions();
    if (action === 'remove-exception') removeException(actionEl.dataset.rule);
    if (action === 'back-exc-list') backToExcList();
    if (action === 'validate-exceptions') validateExceptions(true);
    if (action === 'delete-current-exception') deleteCurrentException();
    if (action === 'save-exceptions') saveExceptions();
}

function togglePasswordVisibility(button) {
    var input = document.getElementById(button.dataset.target || '');
    if (!input) return;

    var visible = input.type === 'text';
    input.type = visible ? 'password' : 'text';
    button.textContent = visible ? 'Show' : 'Hide';
    button.setAttribute('aria-label', visible ? 'Show password' : 'Hide password');
}

function wireStaticHandlers() {
    document.querySelectorAll('.nav-btn[data-page]').forEach(function (button) {
        button.addEventListener('click', function () { showPage(button.dataset.page); });
    });

    document.addEventListener('click', function (event) {
        var actionEl = event.target.closest('[data-action]');
        if (!actionEl) return;
        event.preventDefault();
        handleAction(actionEl);
    });

    document.addEventListener('change', function (event) {
        var target = event.target;
        if (target.id === 'rules-select-all') {
            toggleVisibleRulesSelection(target.checked);
            return;
        }
        if (target.matches('[data-rule-select]')) {
            toggleRuleSelection(target.dataset.key, target.dataset.enabled !== 'false', target.checked);
        }
    });

    var formBindings = [
        ['login-form-credentials', handleLogin],
        ['login-form-newpassword', handleNewPassword],
        ['login-form-mfa', handleMfa],
        ['login-form-forgot', handleForgotPassword],
        ['login-form-reset', handleResetPassword],
    ];
    formBindings.forEach(function (binding) {
        var form = document.getElementById(binding[0]);
        if (form) form.addEventListener('submit', binding[1]);
    });

    var rulesSearch = document.getElementById('rules-search');
    if (rulesSearch) rulesSearch.addEventListener('input', debouncedRenderRules);

    var alertSearch = document.getElementById('alert-rule-filter');
    if (alertSearch) alertSearch.addEventListener('input', debouncedRenderAlerts);

    var alertSeverity = document.getElementById('alert-severity-filter');
    if (alertSeverity) alertSeverity.addEventListener('change', function () { loadAlerts(); });

    var alertHours = document.getElementById('alert-hours-filter');
    if (alertHours) alertHours.addEventListener('change', function () { loadAlerts(); });
}

(function init() {
    wireStaticHandlers();
    if (isAuthenticated()) {
        setHidden('login-screen', true);
        setHidden('app', false);
        document.getElementById('user-email').textContent = getUserEmail();
        loadOverview();
    }
})();
