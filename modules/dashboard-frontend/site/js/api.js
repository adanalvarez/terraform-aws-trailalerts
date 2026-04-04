/**
 * api.js — Authenticated API helper with automatic 401 token refresh.
 *
 * Globals defined here: api()
 *
 * Depends on: CONFIG (inline), accessToken (auth.js), refreshTokens() (auth.js), toast() (ui.js)
 */
'use strict';

/**
 * Make an authenticated API request.
 * Automatically retries once on 401 after refreshing the Cognito tokens.
 *
 * @param {string} path     - API path (e.g. "/api/rules").
 * @param {Object} [options] - fetch options (method, body, headers, etc.)
 * @returns {Promise<Object>} Parsed JSON response.
 */
async function api(path, options) {
    options = options || {};

    var makeRequest = function () {
        return fetch(CONFIG.apiEndpoint + path, {
            method:  options.method  || 'GET',
            body:    options.body    || undefined,
            headers: Object.assign(
                { 'Authorization': 'Bearer ' + accessToken, 'Content-Type': 'application/json' },
                options.headers || {}
            ),
        });
    };

    var resp = await makeRequest();

    // Attempt transparent token refresh on 401
    if (resp.status === 401) {
        var refreshed = await refreshTokens();
        if (refreshed) resp = await makeRequest();
        if (resp.status === 401) {
            toast('Session expired. Please sign in again.', 'error');
            setTimeout(function () { sessionStorage.clear(); window.location.reload(); }, 1500);
            throw new Error('Unauthorized');
        }
    }

    var data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'API error');
    return data;
}
