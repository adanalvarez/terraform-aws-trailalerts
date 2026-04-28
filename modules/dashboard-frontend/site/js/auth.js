/**
 * auth.js — Cognito authentication (USER_PASSWORD_AUTH).
 *
 * Handles: login, new-password challenge, MFA, forgot/reset password,
 * token storage, refresh, logout.
 *
 * Globals defined here:
 *   accessToken, idToken,
 *   cognitoRequest(), handleLogin(), handleNewPassword(), handleMfa(),
 *   handleForgotPassword(), handleResetPassword(), showForgotPassword(),
 *   showLoginStep(), completeAuth(), refreshTokens(), logout(),
 *   isAuthenticated(), getUserEmail()
 *
 * Depends on: CONFIG (config.js), toast() / setHidden() (ui.js), loadOverview() (overview.js runtime only)
 */
'use strict';

var COGNITO_IDP = 'https://cognito-idp.' + CONFIG.region + '.amazonaws.com/';

var accessToken  = null;
var idToken      = null;
var authSession  = null;   // Cognito challenge session token
var authUsername  = null;   // Username carried across challenge steps

// -------------------------------------------------------
// Cognito API Helper
// -------------------------------------------------------

async function cognitoRequest(action, body) {
    var resp = await fetch(COGNITO_IDP, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-amz-json-1.1',
            'X-Amz-Target': 'AWSCognitoIdentityProviderService.' + action,
        },
        body: JSON.stringify(body),
    });
    var data = await resp.json();
    if (!resp.ok) {
        var msg = data.message || data.__type || 'Authentication failed';
        throw new Error(msg);
    }
    return data;
}

// -------------------------------------------------------
// Login Step Management
// -------------------------------------------------------

function showLoginStep(step) {
    document.querySelectorAll('.login-step').forEach(function (s) { s.classList.remove('active'); });
    document.getElementById('login-step-' + step).classList.add('active');
    hideLoginError();
}

function showLoginError(msg) {
    var el = document.getElementById('login-error');
    el.textContent = msg;
    el.classList.add('visible');
}

function hideLoginError() {
    document.getElementById('login-error').classList.remove('visible');
}

function setLoginLoading(btnId, loading) {
    document.getElementById(btnId).disabled = loading;
}

// -------------------------------------------------------
// Login Flow
// -------------------------------------------------------

async function handleLogin(e) {
    e.preventDefault();
    hideLoginError();
    setLoginLoading('login-btn', true);

    authUsername = document.getElementById('login-email').value.trim();
    var password = document.getElementById('login-password').value;

    try {
        var result = await cognitoRequest('InitiateAuth', {
            AuthFlow: 'USER_PASSWORD_AUTH',
            ClientId: CONFIG.cognitoClientId,
            AuthParameters: { USERNAME: authUsername, PASSWORD: password },
        });

        if (result.AuthenticationResult) {
            completeAuth(result.AuthenticationResult);
        } else if (result.ChallengeName === 'NEW_PASSWORD_REQUIRED') {
            authSession = result.Session;
            showLoginStep('newpassword');
        } else if (result.ChallengeName === 'SOFTWARE_TOKEN_MFA') {
            authSession = result.Session;
            showLoginStep('mfa');
        } else {
            showLoginError('Unexpected authentication challenge.');
        }
    } catch (err) {
        showLoginError(err.message);
    } finally {
        setLoginLoading('login-btn', false);
    }
}

// -------------------------------------------------------
// New Password Challenge
// -------------------------------------------------------

async function handleNewPassword(e) {
    e.preventDefault();
    hideLoginError();

    var newPass     = document.getElementById('new-password').value;
    var confirmPass = document.getElementById('confirm-password').value;
    if (newPass !== confirmPass) {
        showLoginError('Passwords do not match.');
        return;
    }

    setLoginLoading('newpass-btn', true);
    try {
        var result = await cognitoRequest('RespondToAuthChallenge', {
            ChallengeName: 'NEW_PASSWORD_REQUIRED',
            ClientId: CONFIG.cognitoClientId,
            Session: authSession,
            ChallengeResponses: { USERNAME: authUsername, NEW_PASSWORD: newPass },
        });

        if (result.AuthenticationResult) {
            completeAuth(result.AuthenticationResult);
        } else if (result.ChallengeName === 'SOFTWARE_TOKEN_MFA') {
            authSession = result.Session;
            showLoginStep('mfa');
        } else {
            showLoginError('Unexpected challenge after password change.');
        }
    } catch (err) {
        showLoginError(err.message);
    } finally {
        setLoginLoading('newpass-btn', false);
    }
}

// -------------------------------------------------------
// MFA Challenge
// -------------------------------------------------------

async function handleMfa(e) {
    e.preventDefault();
    hideLoginError();
    setLoginLoading('mfa-btn', true);

    var code = document.getElementById('mfa-code').value.trim();

    try {
        var result = await cognitoRequest('RespondToAuthChallenge', {
            ChallengeName: 'SOFTWARE_TOKEN_MFA',
            ClientId: CONFIG.cognitoClientId,
            Session: authSession,
            ChallengeResponses: { USERNAME: authUsername, SOFTWARE_TOKEN_MFA_CODE: code },
        });

        if (result.AuthenticationResult) {
            completeAuth(result.AuthenticationResult);
        } else {
            showLoginError('Unexpected response after MFA verification.');
        }
    } catch (err) {
        showLoginError(err.message);
        document.getElementById('mfa-code').value = '';
    } finally {
        setLoginLoading('mfa-btn', false);
    }
}

// -------------------------------------------------------
// Forgot / Reset Password
// -------------------------------------------------------

function showForgotPassword() {
    document.getElementById('forgot-email').value = document.getElementById('login-email').value;
    showLoginStep('forgot');
}

async function handleForgotPassword(e) {
    e.preventDefault();
    hideLoginError();
    setLoginLoading('forgot-btn', true);

    var email = document.getElementById('forgot-email').value.trim();

    try {
        await cognitoRequest('ForgotPassword', {
            ClientId: CONFIG.cognitoClientId,
            Username: email,
        });
        authUsername = email;
        showLoginStep('reset');
    } catch (err) {
        showLoginError(err.message);
    } finally {
        setLoginLoading('forgot-btn', false);
    }
}

async function handleResetPassword(e) {
    e.preventDefault();
    hideLoginError();

    var code        = document.getElementById('reset-code').value.trim();
    var newPass     = document.getElementById('reset-password').value;
    var confirmPass = document.getElementById('reset-confirm').value;
    if (newPass !== confirmPass) {
        showLoginError('Passwords do not match.');
        return;
    }

    setLoginLoading('reset-btn', true);
    try {
        await cognitoRequest('ConfirmForgotPassword', {
            ClientId: CONFIG.cognitoClientId,
            Username: authUsername,
            ConfirmationCode: code,
            Password: newPass,
        });
        toast('Password reset successfully. Please sign in.', 'success');
        showLoginStep('credentials');
        document.getElementById('login-password').value = '';
    } catch (err) {
        showLoginError(err.message);
    } finally {
        setLoginLoading('reset-btn', false);
    }
}

// -------------------------------------------------------
// Complete Auth — store tokens, show app
// -------------------------------------------------------

function completeAuth(authResult) {
    accessToken = authResult.AccessToken;
    idToken     = authResult.IdToken;
    sessionStorage.setItem('access_token', accessToken);
    sessionStorage.setItem('id_token', idToken);
    if (authResult.RefreshToken) {
        sessionStorage.setItem('refresh_token', authResult.RefreshToken);
    }

    // Clear sensitive auth state
    authSession  = null;
    authUsername  = null;
    document.getElementById('login-password').value = '';

    setHidden('login-screen', true);
    setHidden('app', false);
    document.getElementById('user-email').textContent = getUserEmail();
    loadOverview();
}

// -------------------------------------------------------
// Token Refresh
// -------------------------------------------------------

async function refreshTokens() {
    var refreshToken = sessionStorage.getItem('refresh_token');
    if (!refreshToken) return false;

    try {
        var result = await cognitoRequest('InitiateAuth', {
            AuthFlow: 'REFRESH_TOKEN_AUTH',
            ClientId: CONFIG.cognitoClientId,
            AuthParameters: { REFRESH_TOKEN: refreshToken },
        });
        if (result.AuthenticationResult) {
            accessToken = result.AuthenticationResult.AccessToken;
            idToken     = result.AuthenticationResult.IdToken;
            sessionStorage.setItem('access_token', accessToken);
            sessionStorage.setItem('id_token', idToken);
            return true;
        }
    } catch (_) { /* refresh failed */ }
    return false;
}

// -------------------------------------------------------
// Logout
// -------------------------------------------------------

function logout() {
    if (accessToken) {
        cognitoRequest('GlobalSignOut', { AccessToken: accessToken }).catch(function () {});
    }
    sessionStorage.clear();
    accessToken = null;
    idToken     = null;
    window.location.reload();
}

// -------------------------------------------------------
// Token Inspection
// -------------------------------------------------------

function isAuthenticated() {
    accessToken = sessionStorage.getItem('access_token');
    idToken     = sessionStorage.getItem('id_token');
    if (!accessToken || !idToken) return false;

    // Check JWT expiry
    try {
        var payload = JSON.parse(atob(idToken.split('.')[1]));
        if (payload.exp && Date.now() >= payload.exp * 1000) return false;
    } catch (_) { return false; }
    return true;
}

function getUserEmail() {
    if (!idToken) return '';
    try {
        var payload = JSON.parse(atob(idToken.split('.')[1]));
        return payload.email || payload['cognito:username'] || '';
    } catch (_) { return ''; }
}
